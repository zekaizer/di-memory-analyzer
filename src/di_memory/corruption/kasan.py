"""KASAN 기반 fault 분석 모듈."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.analyzers.slub import SlubAnalyzer


class KasanFaultAnalyzer:
    """KASAN 기반 메모리 fault 분석.

    KasanAnalyzer와 SlubAnalyzer를 조합하여 fault 원인을 분석.
    """

    def __init__(
        self,
        kasan: KasanAnalyzer,
        slub: SlubAnalyzer | None = None,
    ) -> None:
        """
        KasanFaultAnalyzer 초기화.

        Args:
            kasan: KasanAnalyzer 인스턴스
            slub: SlubAnalyzer 인스턴스 (선택적, SLUB 연동용)
        """
        self._kasan = kasan
        self._slub = slub

    def analyze_fault(self, fault_addr: int, access_size: int = 8) -> dict:
        """Fault 상세 분석.

        KASAN 태그 정보와 SLUB 메타데이터를 조합하여 fault 원인 분석.

        Args:
            fault_addr: Fault 발생 주소 (tagged pointer)
            access_size: 접근 크기 (bytes)

        Returns:
            dict: {
                fault_addr: int - 원본 주소,
                untagged_addr: int - 태그 제거된 주소,
                access_size: int - 접근 크기,
                ptr_tag: int - 포인터 태그,
                mem_tag: int - 메모리 태그,
                bug_type: str - 버그 유형,
                object_bounds?: dict - 추정 object 경계,
                cache_name?: str - SLUB cache 이름,
                object_addr?: int - object 시작 주소,
                object_index?: int - slab 내 인덱스,
                alloc_track?: dict - 할당 정보,
                free_track?: dict - 해제 정보,
            }
        """
        ptr_tag = self._kasan.get_tag(fault_addr)
        untagged = self._kasan.reset_tag(fault_addr)
        mem_tag = self._kasan.get_mem_tag(untagged)
        bug_type = self._kasan.classify_bug_type(mem_tag)

        result: dict = {
            "fault_addr": fault_addr,
            "untagged_addr": untagged,
            "access_size": access_size,
            "ptr_tag": ptr_tag,
            "mem_tag": mem_tag,
            "bug_type": bug_type,
        }

        # Object 경계 추정 (태그 기반)
        bounds = self._kasan.find_object_bounds(untagged)
        if bounds:
            result["object_bounds"] = {"start": bounds[0], "end": bounds[1]}

        # SLUB 연동
        if self._slub is not None:
            self._add_slub_info(result, untagged)

        return result

    def _add_slub_info(self, result: dict, untagged_addr: int) -> None:
        """SLUB 관련 정보 추가.

        Args:
            result: 결과 dict (수정됨)
            untagged_addr: 태그 제거된 주소
        """
        if self._slub is None:
            return

        cache_info = self._slub.find_owning_cache(untagged_addr)
        if cache_info is None:
            return

        cache, slab, aligned_obj, idx = cache_info
        result["cache_name"] = self._slub.get_cache_name(cache)
        result["object_addr"] = aligned_obj
        result["object_index"] = idx

        # Track 정보
        alloc_track = self._kasan.get_alloc_track(cache, aligned_obj)
        if alloc_track:
            result["alloc_track"] = alloc_track

        free_track = self._kasan.get_free_track(cache, aligned_obj)
        if free_track and free_track.get("stack"):
            result["free_track"] = free_track

    def find_nearby_objects(self, addr: int, search_range: int = 256) -> list[dict]:
        """주변 object 검색.

        SLUB cache에서 주어진 주소 근처의 object들을 찾음.

        Args:
            addr: 검색 중심 주소
            search_range: 검색 범위 (bytes, 앞뒤로)

        Returns:
            list[dict]: [
                {
                    addr: int,
                    tag: int,
                    cache_name?: str,
                    is_free?: bool,
                },
                ...
            ]
        """
        untagged = self._kasan.reset_tag(addr)
        start = max(0, untagged - search_range)
        end = untagged + search_range

        objects: list[dict] = []
        granule_size = self._kasan.GRANULE_SIZE

        # 태그 변화 지점 찾기
        prev_tag = None
        for granule_addr in range(
            self._kasan.round_down(start),
            self._kasan.round_up(end),
            granule_size,
        ):
            mem_tag = self._kasan.get_mem_tag(granule_addr)

            if prev_tag is not None and prev_tag != mem_tag:
                obj_info: dict = {
                    "addr": granule_addr,
                    "tag": mem_tag,
                }

                # SLUB 정보 추가
                if self._slub is not None:
                    cache_info = self._slub.find_owning_cache(granule_addr)
                    if cache_info:
                        cache, slab, aligned_obj, idx = cache_info
                        obj_info["cache_name"] = self._slub.get_cache_name(cache)
                        obj_info["object_addr"] = aligned_obj
                        obj_info["is_free"] = self._slub.is_object_free(
                            slab, aligned_obj
                        )

                objects.append(obj_info)

            prev_tag = mem_tag

        return objects

    def analyze_uaf(self, ptr: int) -> dict | None:
        """Use-after-free 상세 분석.

        Args:
            ptr: 의심 포인터 (tagged)

        Returns:
            dict: UAF 분석 결과 또는 None (UAF 아님)
        """
        untagged = self._kasan.reset_tag(ptr)
        mem_tag = self._kasan.get_mem_tag(untagged)

        if mem_tag != self._kasan.TAG_INVALID:
            return None

        result: dict = {
            "ptr": ptr,
            "untagged_addr": untagged,
            "ptr_tag": self._kasan.get_tag(ptr),
            "mem_tag": mem_tag,
            "bug_type": "use-after-free",
        }

        # SLUB에서 free 정보 찾기
        if self._slub is not None:
            cache_info = self._slub.find_owning_cache(untagged)
            if cache_info:
                cache, slab, aligned_obj, idx = cache_info
                result["cache_name"] = self._slub.get_cache_name(cache)
                result["object_addr"] = aligned_obj

                # Alloc/Free track
                alloc_track = self._kasan.get_alloc_track(cache, aligned_obj)
                if alloc_track:
                    result["alloc_track"] = alloc_track

                free_track = self._kasan.get_free_track(cache, aligned_obj)
                if free_track:
                    result["free_track"] = free_track

        return result

    def analyze_oob(self, ptr: int, access_size: int) -> dict | None:
        """Out-of-bounds 상세 분석.

        Args:
            ptr: 의심 포인터 (tagged)
            access_size: 접근 크기

        Returns:
            dict: OOB 분석 결과 또는 None (OOB 아님)
        """
        check_result = self._kasan.check_access(ptr, access_size)
        if check_result["valid"]:
            return None

        ptr_tag = check_result["ptr_tag"]
        first_bad = check_result["first_mismatch"]
        if first_bad is None:
            return None

        mem_tag = self._kasan.get_mem_tag(first_bad)

        # OOB는 태그가 다르지만 invalid가 아닌 경우
        if mem_tag == self._kasan.TAG_INVALID:
            return None  # UAF

        result: dict = {
            "ptr": ptr,
            "untagged_addr": self._kasan.reset_tag(ptr),
            "access_size": access_size,
            "ptr_tag": ptr_tag,
            "first_bad_addr": first_bad,
            "first_bad_tag": mem_tag,
            "bug_type": "out-of-bounds",
        }

        # Object 경계 추정
        bounds = self._kasan.find_object_bounds(self._kasan.reset_tag(ptr))
        if bounds:
            result["object_bounds"] = {"start": bounds[0], "end": bounds[1]}
            result["overflow_offset"] = first_bad - bounds[1]

        return result
