"""Freelist corruption 탐지 모듈."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

from di_memory.corruption.bitflip import BitflipAnalyzer

if TYPE_CHECKING:
    from di_memory.analyzers.slub import SlubAnalyzer


class FreelistCorruptionDetector:
    """SLUB freelist corruption 탐지."""

    def __init__(self, slub: SlubAnalyzer) -> None:
        """
        FreelistCorruptionDetector 초기화.

        Args:
            slub: SlubAnalyzer 인스턴스
        """
        self._slub = slub
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
        cache = self._slub._get_slab_cache(slab)
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
