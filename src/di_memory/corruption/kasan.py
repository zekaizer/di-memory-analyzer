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

    # =========================================================================
    # RedZone 분석
    # =========================================================================

    def analyze_redzone(self, obj_addr: int, obj_size: int) -> dict:
        """
        Redzone 오염 분석.

        Object 앞뒤 redzone의 태그를 분석하여 overflow/underflow 탐지.

        Args:
            obj_addr: Object 시작 주소
            obj_size: Object 크기 (bytes)

        Returns:
            dict: {
                "valid": bool - redzone 무결성,
                "left_redzone": dict - 왼쪽 redzone 상태,
                "right_redzone": dict - 오른쪽 redzone 상태,
                "corruption_type": str | None - underflow/overflow/both,
                "corrupted_granules": int - 오염된 granule 수,
            }
        """
        if not self._kasan.is_enabled:
            return {"valid": True, "corruption_type": None, "corrupted_granules": 0}

        untagged = self._kasan.reset_tag(obj_addr)
        granule_size = self._kasan.GRANULE_SIZE
        obj_tag = self._kasan.get_mem_tag(untagged)

        # 왼쪽 redzone 검사 (object 앞 최대 2 granule)
        left_corrupted = 0
        left_start = max(0, untagged - granule_size * 2)
        for addr in range(left_start, untagged, granule_size):
            tag = self._kasan.get_mem_tag(addr)
            # redzone은 TAG_INVALID여야 함
            if tag != self._kasan.TAG_INVALID and tag == obj_tag:
                left_corrupted += 1

        # 오른쪽 redzone 검사 (object 끝 뒤 최대 2 granule)
        obj_end = self._kasan.round_up(untagged + obj_size)
        right_corrupted = 0
        for addr in range(obj_end, obj_end + granule_size * 2, granule_size):
            tag = self._kasan.get_mem_tag(addr)
            # redzone이어야 하는데 object 태그와 같으면 overflow
            if tag != self._kasan.TAG_INVALID and tag == obj_tag:
                right_corrupted += 1

        # Corruption 유형 결정
        corruption_type = None
        if left_corrupted > 0 and right_corrupted > 0:
            corruption_type = "both"
        elif left_corrupted > 0:
            corruption_type = "underflow"
        elif right_corrupted > 0:
            corruption_type = "overflow"

        return {
            "valid": corruption_type is None,
            "left_redzone": {
                "start": left_start,
                "corrupted_granules": left_corrupted,
            },
            "right_redzone": {
                "start": obj_end,
                "corrupted_granules": right_corrupted,
            },
            "corruption_type": corruption_type,
            "corrupted_granules": left_corrupted + right_corrupted,
        }

    # =========================================================================
    # 시간순 Corruption 추적
    # =========================================================================

    def build_corruption_timeline(self, addr: int) -> dict:
        """
        Corruption 타임라인 구성.

        KASAN alloc/free track과 현재 상태를 조합하여 타임라인 구성.

        Args:
            addr: 분석할 주소

        Returns:
            dict: {
                "addr": int,
                "current_state": str,
                "alloc_track": dict | None,
                "free_track": dict | None,
                "timeline": list[dict] - 시간순 이벤트,
                "likely_scenario": str,
            }
        """
        if not self._kasan.is_enabled:
            return {
                "addr": addr,
                "current_state": "unknown",
                "timeline": [],
                "likely_scenario": "kasan_disabled",
            }

        untagged = self._kasan.reset_tag(addr)
        mem_tag = self._kasan.get_mem_tag(untagged)

        # 현재 상태 결정
        if mem_tag == self._kasan.TAG_INVALID:
            current_state = "freed"
        elif mem_tag == self._kasan.TAG_KERNEL:
            current_state = "kernel"
        else:
            current_state = "allocated"

        result: dict = {
            "addr": addr,
            "untagged_addr": untagged,
            "current_state": current_state,
            "current_tag": mem_tag,
            "alloc_track": None,
            "free_track": None,
            "timeline": [],
            "likely_scenario": "unknown",
        }

        # SLUB에서 추가 정보
        if self._slub is not None:
            cache_info = self._slub.find_owning_cache(untagged)
            if cache_info:
                cache, slab, aligned_obj, idx = cache_info
                result["cache_name"] = self._slub.get_cache_name(cache)
                result["object_addr"] = aligned_obj

                # Alloc/Free track
                alloc_track = self._kasan.get_alloc_track(cache, aligned_obj)
                free_track = self._kasan.get_free_track(cache, aligned_obj)

                if alloc_track:
                    result["alloc_track"] = alloc_track
                    result["timeline"].append({
                        "event": "alloc",
                        "pid": alloc_track.get("pid"),
                        "stack": alloc_track.get("stack", []),
                    })

                if free_track and free_track.get("stack"):
                    result["free_track"] = free_track
                    result["timeline"].append({
                        "event": "free",
                        "pid": free_track.get("pid"),
                        "stack": free_track.get("stack", []),
                    })

                # Freelist 상태 확인
                is_in_freelist = self._slub.is_object_free(slab, aligned_obj)
                result["in_freelist"] = is_in_freelist

                # 시나리오 추론
                result["likely_scenario"] = self._infer_scenario(
                    current_state, is_in_freelist, alloc_track, free_track
                )

        return result

    def _infer_scenario(
        self,
        current_state: str,
        in_freelist: bool,
        alloc_track: dict | None,
        free_track: dict | None,
    ) -> str:
        """
        Corruption 시나리오 추론.

        Args:
            current_state: 현재 KASAN 상태
            in_freelist: freelist에 있는지
            alloc_track: 할당 정보
            free_track: 해제 정보

        Returns:
            시나리오 설명 문자열
        """
        has_alloc = alloc_track is not None
        has_free = free_track is not None and free_track.get("stack")

        if current_state == "freed" and not in_freelist:
            return "use-after-free-realloc"  # 해제 후 재할당 시도
        if current_state == "freed" and in_freelist:
            if has_alloc and has_free:
                return "normal-free"  # 정상 해제
            return "freed-no-track"
        if current_state == "allocated" and in_freelist:
            return "freelist-corruption"  # freelist는 free인데 KASAN은 allocated
        if current_state == "allocated" and not in_freelist:
            if has_alloc:
                return "normal-alloc"  # 정상 할당 상태
            return "allocated-no-track"

        return "unknown"

    # =========================================================================
    # Multi-object Corruption 탐지
    # =========================================================================

    def detect_spray_corruption(
        self, start: int, range_size: int, expected_tag: int | None = None
    ) -> dict:
        """
        광범위 corruption 탐지 (heap spray 등).

        넓은 메모리 영역의 태그 패턴을 분석하여 비정상적 패턴 탐지.

        Args:
            start: 검색 시작 주소
            range_size: 검색 범위 (bytes)
            expected_tag: 예상 태그 (None이면 자동 추론)

        Returns:
            dict: {
                "start": int,
                "range_size": int,
                "total_granules": int,
                "tag_distribution": dict[int, int] - 태그별 granule 수,
                "anomalies": list[dict] - 비정상 패턴,
                "corruption_indicators": dict,
            }
        """
        if not self._kasan.is_enabled:
            return {
                "start": start,
                "range_size": range_size,
                "total_granules": 0,
                "tag_distribution": {},
                "anomalies": [],
                "corruption_indicators": {"checked": False},
            }

        untagged = self._kasan.reset_tag(start)
        granule_size = self._kasan.GRANULE_SIZE
        aligned_start = self._kasan.round_down(untagged)
        aligned_end = self._kasan.round_up(untagged + range_size)

        # 태그 수집
        tag_distribution: dict[int, int] = {}
        tag_sequence: list[tuple[int, int]] = []  # (addr, tag)

        for addr in range(aligned_start, aligned_end, granule_size):
            tag = self._kasan.get_mem_tag(addr)
            tag_distribution[tag] = tag_distribution.get(tag, 0) + 1
            tag_sequence.append((addr, tag))

        total_granules = len(tag_sequence)
        anomalies: list[dict] = []

        # 비정상 패턴 탐지
        # 1. 연속된 TAG_INVALID (대량 해제)
        consecutive_invalid = 0
        invalid_start = None
        for addr, tag in tag_sequence:
            if tag == self._kasan.TAG_INVALID:
                if invalid_start is None:
                    invalid_start = addr
                consecutive_invalid += 1
            else:
                if consecutive_invalid > 8:  # 8 granule = 128 bytes 이상
                    anomalies.append({
                        "type": "mass_free",
                        "start": invalid_start,
                        "granules": consecutive_invalid,
                        "size": consecutive_invalid * granule_size,
                    })
                consecutive_invalid = 0
                invalid_start = None

        # 마지막 검사
        if consecutive_invalid > 8:
            anomalies.append({
                "type": "mass_free",
                "start": invalid_start,
                "granules": consecutive_invalid,
                "size": consecutive_invalid * granule_size,
            })

        # 2. 동일 태그 반복 (heap spray)
        if expected_tag is None and tag_distribution:
            # 가장 흔한 태그 찾기 (INVALID, KERNEL 제외)
            valid_tags = {
                k: v for k, v in tag_distribution.items()
                if k not in (self._kasan.TAG_INVALID, self._kasan.TAG_KERNEL)
            }
            if valid_tags:
                expected_tag = max(valid_tags, key=lambda k: valid_tags[k])

        if expected_tag is not None:
            expected_count = tag_distribution.get(expected_tag, 0)
            if expected_count > total_granules * 0.8:  # 80% 이상 동일 태그
                anomalies.append({
                    "type": "heap_spray",
                    "dominant_tag": expected_tag,
                    "coverage": expected_count / total_granules,
                    "granules": expected_count,
                })

        # 3. 이상한 태그 값 (메모리 오염)
        for tag, count in tag_distribution.items():
            # 일반적이지 않은 태그 패턴
            if 0xF0 <= tag < 0xFE and tag != self._kasan.TAG_INVALID:
                anomalies.append({
                    "type": "unusual_tag",
                    "tag": tag,
                    "count": count,
                })

        # Corruption 지표
        invalid_ratio = tag_distribution.get(self._kasan.TAG_INVALID, 0) / max(1, total_granules)
        unique_tags = len([t for t in tag_distribution if t not in (
            self._kasan.TAG_INVALID, self._kasan.TAG_KERNEL
        )])

        return {
            "start": aligned_start,
            "range_size": aligned_end - aligned_start,
            "total_granules": total_granules,
            "tag_distribution": tag_distribution,
            "anomalies": anomalies,
            "corruption_indicators": {
                "checked": True,
                "invalid_ratio": invalid_ratio,
                "unique_valid_tags": unique_tags,
                "has_mass_free": any(a["type"] == "mass_free" for a in anomalies),
                "has_heap_spray": any(a["type"] == "heap_spray" for a in anomalies),
            },
        }

    def find_corrupted_objects_in_slab(self, slab_addr: int) -> list[dict]:
        """
        Slab 내 corrupted object 탐지.

        SLUB slab 내 모든 object의 KASAN 상태를 검사.

        Args:
            slab_addr: slab 주소

        Returns:
            list[dict]: [{object_addr, index, issue, details}, ...]
        """
        if self._slub is None:
            return []

        if not self._kasan.is_enabled:
            return []

        corrupted: list[dict] = []

        # slab 구조체 읽기
        slab = self._slub._structs.read(slab_addr, "struct slab")
        if slab is None:
            return []

        cache = self._slub._get_slab_cache(slab)
        base = self._slub.slab_to_virt(slab)
        obj_size = cache.size

        for idx in range(slab.objects):
            obj_addr = base + idx * obj_size
            is_free = self._slub.is_object_free(slab, obj_addr)
            mem_tag = self._kasan.get_mem_tag(obj_addr)

            # 불일치 검사
            if is_free and mem_tag != self._kasan.TAG_INVALID:
                corrupted.append({
                    "object_addr": obj_addr,
                    "index": idx,
                    "issue": "freed_with_valid_tag",
                    "expected_tag": self._kasan.TAG_INVALID,
                    "actual_tag": mem_tag,
                    "details": f"Object is free but has tag 0x{mem_tag:02x}",
                })
            elif not is_free and mem_tag == self._kasan.TAG_INVALID:
                corrupted.append({
                    "object_addr": obj_addr,
                    "index": idx,
                    "issue": "allocated_with_invalid_tag",
                    "expected_tag": "valid (not 0xFE)",
                    "actual_tag": mem_tag,
                    "details": "Object is allocated but has TAG_INVALID",
                })

            # Redzone 검사
            redzone = self.analyze_redzone(obj_addr, obj_size)
            if not redzone["valid"]:
                corrupted.append({
                    "object_addr": obj_addr,
                    "index": idx,
                    "issue": f"redzone_{redzone['corruption_type']}",
                    "corrupted_granules": redzone["corrupted_granules"],
                    "details": f"Redzone corruption: {redzone['corruption_type']}",
                })

        return corrupted
