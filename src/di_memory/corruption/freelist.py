"""Freelist corruption 탐지 모듈."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

from di_memory.corruption.bitflip import BitflipAnalyzer
from di_memory.corruption.helpers import (
    check_object_state_consistency,
    format_state_error,
)

if TYPE_CHECKING:
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.analyzers.slub import SlubAnalyzer


class FreelistCorruptionDetector:
    """SLUB freelist corruption 탐지."""

    def __init__(
        self,
        slub: SlubAnalyzer,
        kasan: KasanAnalyzer | None = None,
    ) -> None:
        """
        FreelistCorruptionDetector 초기화.

        Args:
            slub: SlubAnalyzer 인스턴스
            kasan: KasanAnalyzer 인스턴스 (선택적, KASAN 연동용)
        """
        self._slub = slub
        self._kasan = kasan
        self._bitflip = BitflipAnalyzer()

    def validate_freelist(self, slab: ctypes.Structure) -> dict:
        """
        Freelist 무결성 검증.

        freelist 체인을 순회하며 corruption 여부 확인.

        Args:
            slab: struct slab

        Returns:
            {
                "valid": bool,
                "free_count": int,
                "expected_free": int,
                "errors": list[dict],
            }
        """
        cache = self._slub.get_slab_cache(slab)
        fp_offset = cache.offset

        freelist_offset = self._slub._backend.offsetof("struct slab", "freelist")
        ptr_addr = slab._base + freelist_offset
        current = slab.freelist

        errors: list[dict] = []
        seen: set[int] = set()  # decoded 주소 기준 cycle 검사
        free_count = 0

        while current != 0:
            decoded = self._slub._decode_freeptr(cache, current, ptr_addr)

            if decoded == 0:
                break

            # cycle 검사 (decoded 기준)
            if decoded in seen:
                errors.append(
                    {
                        "type": "cycle",
                        "ptr_addr": ptr_addr,
                        "encoded_value": current,
                        "decoded_value": decoded,
                        "details": f"Cycle detected at {hex(decoded)}",
                    }
                )
                break
            seen.add(decoded)

            # 유효성 검사
            if not self._slub._is_valid_object_addr(decoded, slab, cache):
                base = self._slub.slab_to_virt(slab)
                end = base + slab.objects * cache.size
                errors.append(
                    {
                        "type": "out_of_bounds",
                        "ptr_addr": ptr_addr,
                        "encoded_value": current,
                        "decoded_value": decoded,
                        "details": f"Decoded {hex(decoded)} outside [{hex(base)}, {hex(end)})",
                    }
                )
                break

            free_count += 1

            # 다음 포인터 읽기
            ptr_addr = decoded + fp_offset
            current = self._slub._backend.read_pointer(ptr_addr)

        expected_free = slab.objects - slab.inuse

        if free_count != expected_free and not errors:
            errors.append(
                {
                    "type": "count_mismatch",
                    "ptr_addr": 0,
                    "encoded_value": 0,
                    "details": f"Free count {free_count} != expected {expected_free}",
                }
            )

        return {
            "valid": len(errors) == 0,
            "free_count": free_count,
            "expected_free": expected_free,
            "errors": errors,
        }

    def trace_corrupted_freeptr(
        self,
        cache: ctypes.Structure,
        ptr_addr: int,
        encoded_value: int,
    ) -> dict:
        """
        Corrupted freelist 포인터 분석.

        FREELIST_HARDENED 환경에서 corruption 발생 시:
        - 원본 값 추정 (bitflip 분석)
        - 예상되는 올바른 encoded 값 계산
        - corruption 패턴 분석

        Args:
            cache: struct kmem_cache
            ptr_addr: 포인터가 저장된 주소
            encoded_value: 읽은 (corrupted) 인코딩 값

        Returns:
            {
                "ptr_addr": int,
                "encoded_value": int,
                "decoded_value": int,
                "expected_range": tuple[int, int],
                "analysis": dict,
                "likely_cause": str,
            }
        """
        decoded = self._slub._decode_freeptr(cache, encoded_value, ptr_addr)

        # 유효한 object 범위 계산 (cache의 일반적인 slab 기준)
        page_size = self._slub._addr.page_size
        expected_base = ptr_addr & ~(page_size - 1)  # 페이지 정렬
        expected_end = expected_base + page_size

        # Bitflip 분석
        analysis = self._bitflip.analyze(decoded, (expected_base, expected_end))

        # 원인 추정
        likely_cause = self._estimate_corruption_cause(decoded, analysis)

        return {
            "ptr_addr": ptr_addr,
            "encoded_value": encoded_value,
            "decoded_value": decoded,
            "expected_range": (expected_base, expected_end),
            "analysis": analysis,
            "likely_cause": likely_cause,
        }

    def _estimate_corruption_cause(self, decoded: int, analysis: dict) -> str:
        """
        Corruption 원인 추정.

        Args:
            decoded: 디코딩된 포인터 값
            analysis: bitflip 분석 결과

        Returns:
            추정 원인 문자열
        """
        if analysis["is_bitflip"]:
            return "bitflip"
        if decoded in (0xDEAD_BEEF, 0xDEAD_DEAD, 0xDEAD_BEEF_DEAD_BEEF):
            return "use_after_free"
        if decoded > 0xFFFF_FFFF_FFFF_0000:
            return "overflow"
        return "unknown"

    def validate_cache_freelists(self, cache: ctypes.Structure) -> dict:
        """
        Cache의 모든 slab freelist 검증.

        Args:
            cache: struct kmem_cache

        Returns:
            {
                "cache_name": str,
                "total_slabs": int,
                "corrupted_slabs": int,
                "errors": list[dict],
            }
        """
        cache_name = self._slub.get_cache_name(cache)
        total_slabs = 0
        corrupted_slabs = 0
        all_errors: list[dict] = []

        for slab in self._slub.iter_slabs(cache):
            total_slabs += 1
            result = self.validate_freelist(slab)
            if not result["valid"]:
                corrupted_slabs += 1
                for err in result["errors"]:
                    err["slab_addr"] = slab._base
                    all_errors.append(err)

        return {
            "cache_name": cache_name,
            "total_slabs": total_slabs,
            "corrupted_slabs": corrupted_slabs,
            "errors": all_errors,
        }

    def validate_all_caches(self) -> dict:
        """
        모든 cache의 freelist 검증.

        Returns:
            {
                "total_caches": int,
                "corrupted_caches": int,
                "results": list[dict],  # validate_cache_freelists 결과들
            }
        """
        results: list[dict] = []
        total_caches = 0
        corrupted_caches = 0

        for cache in self._slub.iter_caches():
            total_caches += 1
            result = self.validate_cache_freelists(cache)
            results.append(result)
            if result["corrupted_slabs"] > 0:
                corrupted_caches += 1

        return {
            "total_caches": total_caches,
            "corrupted_caches": corrupted_caches,
            "results": results,
        }

    # =========================================================================
    # KASAN 연동 검증
    # =========================================================================

    def validate_freelist_with_kasan(self, slab: ctypes.Structure) -> dict:
        """
        Freelist + KASAN 통합 검증.

        freelist와 KASAN shadow 상태를 교차 검증.

        Args:
            slab: struct slab

        Returns:
            {
                "valid": bool,
                "freelist_result": dict - 기본 freelist 검증 결과,
                "kasan_errors": list[dict] - KASAN 불일치 목록,
                "consistency": dict - 일관성 통계,
            }
        """
        freelist_result = self.validate_freelist(slab)

        if self._kasan is None or not self._kasan.is_enabled:
            return {
                "valid": freelist_result["valid"],
                "freelist_result": freelist_result,
                "kasan_errors": [],
                "consistency": {"checked": False},
            }

        cache = self._slub.get_slab_cache(slab)
        base = self._slub.slab_to_virt(slab)
        obj_size = cache.size

        # Freelist에 있는 object 주소들
        free_objects = self._collect_free_objects(slab)

        kasan_errors: list[dict] = []
        freed_but_valid_tag = 0
        allocated_but_invalid_tag = 0

        for idx in range(slab.objects):
            obj_addr = base + idx * obj_size
            is_in_freelist = obj_addr in free_objects
            mem_tag = self._kasan.get_mem_tag(obj_addr)

            is_consistent, error_type = check_object_state_consistency(
                is_in_freelist, mem_tag, self._kasan
            )

            if not is_consistent and error_type:
                if error_type == "freed_but_valid_tag":
                    freed_but_valid_tag += 1
                elif error_type == "allocated_but_invalid_tag":
                    allocated_but_invalid_tag += 1

                kasan_errors.append(
                    format_state_error(error_type, obj_addr, idx, mem_tag)
                )

        valid = freelist_result["valid"] and len(kasan_errors) == 0

        return {
            "valid": valid,
            "freelist_result": freelist_result,
            "kasan_errors": kasan_errors,
            "consistency": {
                "checked": True,
                "total_objects": slab.objects,
                "free_count": len(free_objects),
                "freed_but_valid_tag": freed_but_valid_tag,
                "allocated_but_invalid_tag": allocated_but_invalid_tag,
            },
        }

    def _collect_free_objects(self, slab: ctypes.Structure) -> set[int]:
        """
        Freelist를 순회하여 free object 주소들 수집.

        Args:
            slab: struct slab

        Returns:
            free object 주소 집합
        """
        cache = self._slub.get_slab_cache(slab)
        fp_offset = cache.offset

        freelist_offset = self._slub._backend.offsetof("struct slab", "freelist")
        ptr_addr = slab._base + freelist_offset
        current = slab.freelist

        free_objects: set[int] = set()
        seen: set[int] = set()

        while current != 0:
            decoded = self._slub._decode_freeptr(cache, current, ptr_addr)

            if decoded == 0 or decoded in seen:
                break
            seen.add(decoded)

            if not self._slub._is_valid_object_addr(decoded, slab, cache):
                break

            free_objects.add(decoded)
            ptr_addr = decoded + fp_offset
            current = self._slub._backend.read_pointer(ptr_addr)

        return free_objects

    def detect_double_free(self, slab: ctypes.Structure) -> list[dict]:
        """
        Double-free 탐지.

        KASAN으로 TAG_INVALID인 object가 freelist에 두 번 등장하는지 탐지.

        Args:
            slab: struct slab

        Returns:
            list[dict]: [{object_addr, count, details}, ...]
        """
        cache = self._slub.get_slab_cache(slab)
        fp_offset = cache.offset

        freelist_offset = self._slub._backend.offsetof("struct slab", "freelist")
        ptr_addr = slab._base + freelist_offset
        current = slab.freelist

        object_count: dict[int, int] = {}
        max_iter = slab.objects * 2  # cycle 방지

        for _ in range(max_iter):
            if current == 0:
                break

            decoded = self._slub._decode_freeptr(cache, current, ptr_addr)
            if decoded == 0:
                break

            if not self._slub._is_valid_object_addr(decoded, slab, cache):
                break

            object_count[decoded] = object_count.get(decoded, 0) + 1

            ptr_addr = decoded + fp_offset
            current = self._slub._backend.read_pointer(ptr_addr)

        # 2번 이상 등장한 object
        double_frees = [
            {
                "object_addr": addr,
                "count": count,
                "details": f"Object appears {count} times in freelist",
            }
            for addr, count in object_count.items()
            if count > 1
        ]

        return double_frees

    def validate_cache_with_kasan(self, cache: ctypes.Structure) -> dict:
        """
        Cache의 모든 slab을 KASAN과 함께 검증.

        Args:
            cache: struct kmem_cache

        Returns:
            {
                "cache_name": str,
                "total_slabs": int,
                "corrupted_slabs": int,
                "kasan_inconsistent_slabs": int,
                "errors": list[dict],
            }
        """
        cache_name = self._slub.get_cache_name(cache)
        total_slabs = 0
        corrupted_slabs = 0
        kasan_inconsistent_slabs = 0
        all_errors: list[dict] = []

        for slab in self._slub.iter_slabs(cache):
            total_slabs += 1
            result = self.validate_freelist_with_kasan(slab)

            if not result["freelist_result"]["valid"]:
                corrupted_slabs += 1
                for err in result["freelist_result"]["errors"]:
                    err["slab_addr"] = slab._base
                    all_errors.append(err)

            if result["kasan_errors"]:
                kasan_inconsistent_slabs += 1
                for err in result["kasan_errors"]:
                    err["slab_addr"] = slab._base
                    all_errors.append(err)

        return {
            "cache_name": cache_name,
            "total_slabs": total_slabs,
            "corrupted_slabs": corrupted_slabs,
            "kasan_inconsistent_slabs": kasan_inconsistent_slabs,
            "errors": all_errors,
        }
