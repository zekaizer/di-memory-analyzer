"""통합 Corruption 탐지 모듈."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.analyzers.slub import SlubAnalyzer

from di_memory.corruption.bitflip import BitflipAnalyzer
from di_memory.corruption.freelist import FreelistCorruptionDetector
from di_memory.corruption.kasan import KasanFaultAnalyzer


class CorruptionDetector:
    """통합 Corruption 탐지기.

    BitflipAnalyzer, FreelistCorruptionDetector, KasanFaultAnalyzer를
    조합하여 다차원 corruption 분석 수행.
    """

    def __init__(
        self,
        slub: SlubAnalyzer,
        kasan: KasanAnalyzer | None = None,
    ) -> None:
        """
        CorruptionDetector 초기화.

        Args:
            slub: SlubAnalyzer 인스턴스
            kasan: KasanAnalyzer 인스턴스 (선택적)
        """
        self._slub = slub
        self._kasan = kasan

        # Sub-detectors
        self._bitflip = BitflipAnalyzer()
        self._freelist = FreelistCorruptionDetector(slub, kasan)
        self._kasan_fault = KasanFaultAnalyzer(kasan, slub) if kasan else None

    @property
    def kasan_enabled(self) -> bool:
        """KASAN 활성화 여부."""
        return self._kasan is not None and self._kasan.is_enabled

    # =========================================================================
    # 통합 분석
    # =========================================================================

    def analyze_corruption(self, addr: int, access_size: int = 8) -> dict:
        """
        다차원 corruption 분석.

        주어진 주소에 대해 모든 가용한 분석 수행.

        Args:
            addr: 분석할 주소
            access_size: 접근 크기 (bytes)

        Returns:
            dict: {
                "addr": int,
                "analyses": dict - 각 분석 결과,
                "likely_cause": str - 추정 원인,
                "severity": str - 심각도 (low/medium/high/critical),
                "recommendations": list[str] - 권장 조치,
            }
        """
        result: dict = {
            "addr": addr,
            "analyses": {},
            "likely_cause": "unknown",
            "severity": "low",
            "recommendations": [],
        }

        # 1. SLUB 분석
        slub_info = self._analyze_slub(addr)
        if slub_info:
            result["analyses"]["slub"] = slub_info

        # 2. KASAN 분석 (enabled일 때만)
        if self.kasan_enabled and self._kasan_fault:
            kasan_info = self._analyze_kasan(addr, access_size)
            result["analyses"]["kasan"] = kasan_info

        # 3. 원인 추론 및 심각도 결정
        self._infer_cause_and_severity(result)

        return result

    def _analyze_slub(self, addr: int) -> dict | None:
        """SLUB 관련 분석."""
        cache_info = self._slub.find_owning_cache(addr)
        if cache_info is None:
            return None

        cache, slab, aligned_obj, idx = cache_info

        return {
            "cache_name": self._slub.get_cache_name(cache),
            "object_addr": aligned_obj,
            "object_index": idx,
            "object_size": cache.size,
            "is_free": self._slub.is_object_free(slab, aligned_obj),
            "slab_addr": slab._base,
        }

    def _analyze_kasan(self, addr: int, access_size: int) -> dict:
        """KASAN 관련 분석."""
        if not self._kasan or not self._kasan_fault:
            return {"enabled": False}

        untagged = self._kasan.reset_tag(addr)
        ptr_tag = self._kasan.get_tag(addr)
        mem_tag = self._kasan.get_mem_tag(untagged)

        result: dict = {
            "enabled": True,
            "ptr_tag": ptr_tag,
            "mem_tag": mem_tag,
            "tags_match": self._kasan.tags_match(ptr_tag, mem_tag),
            "bug_type": self._kasan.classify_bug_type(mem_tag),
        }

        # Access check
        access_check = self._kasan.check_access(addr, access_size)
        result["access_valid"] = access_check["valid"]
        if not access_check["valid"]:
            result["first_mismatch"] = access_check["first_mismatch"]

        # Timeline
        timeline = self._kasan_fault.build_corruption_timeline(addr)
        result["timeline"] = timeline

        return result

    def _infer_cause_and_severity(self, result: dict) -> None:
        """원인 추론 및 심각도 결정."""
        analyses = result["analyses"]
        slub = analyses.get("slub")
        kasan = analyses.get("kasan")

        causes: list[str] = []
        severity_score = 0

        # SLUB 기반 추론
        if slub and slub["is_free"]:
            causes.append("accessing_freed_object")
            severity_score += 3

        # KASAN 기반 추론
        if kasan and kasan.get("enabled"):
            bug_type = kasan.get("bug_type", "")
            if bug_type == "use-after-free":
                causes.append("use_after_free")
                severity_score += 4
            elif bug_type == "out-of-bounds":
                causes.append("out_of_bounds")
                severity_score += 3
            elif bug_type == "tag-mismatch":
                causes.append("tag_mismatch")
                severity_score += 2

            if not kasan.get("access_valid"):
                severity_score += 1

            # Timeline 기반 추론
            timeline = kasan.get("timeline", {})
            scenario = timeline.get("likely_scenario", "")
            if scenario == "freelist-corruption":
                causes.append("freelist_corruption")
                severity_score += 4

        # 최종 결정
        if causes:
            result["likely_cause"] = causes[0]  # 가장 가능성 높은 원인

        if severity_score >= 6:
            result["severity"] = "critical"
        elif severity_score >= 4:
            result["severity"] = "high"
        elif severity_score >= 2:
            result["severity"] = "medium"
        else:
            result["severity"] = "low"

        # 권장 조치
        result["recommendations"] = self._generate_recommendations(causes)

    def _generate_recommendations(self, causes: list[str]) -> list[str]:
        """원인에 따른 권장 조치 생성."""
        recommendations = []

        for cause in causes:
            if cause == "use_after_free":
                recommendations.extend(
                    [
                        "Check object lifecycle management",
                        "Review free_track for deallocation point",
                        "Look for dangling pointer usage",
                    ]
                )
            elif cause == "out_of_bounds":
                recommendations.extend(
                    [
                        "Check array/buffer bounds",
                        "Review loop conditions",
                        "Verify size calculations",
                    ]
                )
            elif cause == "freelist_corruption":
                recommendations.extend(
                    [
                        "Check for heap overflow",
                        "Review adjacent object writes",
                        "Consider memory corruption from other subsystem",
                    ]
                )
            elif cause == "tag_mismatch":
                recommendations.extend(
                    [
                        "Verify pointer provenance",
                        "Check for type confusion",
                    ]
                )

        return list(dict.fromkeys(recommendations))  # 중복 제거

    # =========================================================================
    # Slab 전체 검사
    # =========================================================================

    def scan_slab(self, slab_addr: int) -> dict:
        """
        Slab 전체 corruption 검사.

        Args:
            slab_addr: slab 주소

        Returns:
            dict: {
                "slab_addr": int,
                "freelist_result": dict,
                "kasan_result": dict | None,
                "corrupted_objects": list[dict],
                "summary": dict,
            }
        """
        slab = self._slub.get_slab_by_addr(slab_addr)
        if slab is None:
            return {"slab_addr": slab_addr, "error": "Failed to read slab"}

        result: dict = {
            "slab_addr": slab_addr,
            "freelist_result": None,
            "kasan_result": None,
            "corrupted_objects": [],
            "summary": {},
        }

        # Freelist 검증
        if self.kasan_enabled:
            result["freelist_result"] = self._freelist.validate_freelist_with_kasan(
                slab
            )
        else:
            result["freelist_result"] = self._freelist.validate_freelist(slab)

        # KASAN 기반 object 검사
        if self.kasan_enabled and self._kasan_fault:
            result["corrupted_objects"] = (
                self._kasan_fault.find_corrupted_objects_in_slab(slab_addr)
            )

        # Double-free 검사
        double_frees = self._freelist.detect_double_free(slab)
        if double_frees:
            result["double_frees"] = double_frees

        # Summary
        freelist_valid = result["freelist_result"].get("valid", True)
        kasan_errors = len(result.get("freelist_result", {}).get("kasan_errors", []))
        corrupted_count = len(result["corrupted_objects"])
        double_free_count = len(double_frees) if double_frees else 0

        result["summary"] = {
            "freelist_valid": freelist_valid,
            "kasan_errors": kasan_errors,
            "corrupted_objects": corrupted_count,
            "double_frees": double_free_count,
            "total_issues": (0 if freelist_valid else 1)
            + kasan_errors
            + corrupted_count
            + double_free_count,
        }

        return result

    def scan_cache(self, cache_name: str) -> dict:
        """
        Cache 전체 corruption 검사.

        Args:
            cache_name: cache 이름

        Returns:
            dict: {
                "cache_name": str,
                "total_slabs": int,
                "scanned_slabs": int,
                "corrupted_slabs": int,
                "issues": list[dict],
                "summary": dict,
            }
        """
        cache = self._slub.get_cache(cache_name)
        if cache is None:
            return {"cache_name": cache_name, "error": "Cache not found"}

        result: dict = {
            "cache_name": cache_name,
            "total_slabs": 0,
            "scanned_slabs": 0,
            "corrupted_slabs": 0,
            "issues": [],
            "summary": {},
        }

        for slab in self._slub.iter_slabs(cache):
            result["total_slabs"] += 1
            result["scanned_slabs"] += 1

            slab_result = self.scan_slab(slab._base)
            if slab_result["summary"].get("total_issues", 0) > 0:
                result["corrupted_slabs"] += 1
                result["issues"].append(
                    {
                        "slab_addr": slab._base,
                        "summary": slab_result["summary"],
                    }
                )

        result["summary"] = {
            "total_slabs": result["total_slabs"],
            "corrupted_slabs": result["corrupted_slabs"],
            "corruption_rate": result["corrupted_slabs"]
            / max(1, result["total_slabs"]),
        }

        return result

    def scan_all_caches(self) -> dict:
        """
        모든 cache 검사.

        Returns:
            dict: {
                "total_caches": int,
                "corrupted_caches": int,
                "cache_results": list[dict],
                "summary": dict,
            }
        """
        result: dict = {
            "total_caches": 0,
            "corrupted_caches": 0,
            "cache_results": [],
            "summary": {},
        }

        for cache in self._slub.iter_caches():
            result["total_caches"] += 1
            cache_name = self._slub.get_cache_name(cache)

            # KASAN 연동 검증
            if self.kasan_enabled:
                cache_result = self._freelist.validate_cache_with_kasan(cache)
            else:
                cache_result = self._freelist.validate_cache_freelists(cache)

            if cache_result.get("corrupted_slabs", 0) > 0:
                result["corrupted_caches"] += 1

            result["cache_results"].append(
                {
                    "cache_name": cache_name,
                    "corrupted_slabs": cache_result.get("corrupted_slabs", 0),
                    "kasan_inconsistent": cache_result.get(
                        "kasan_inconsistent_slabs", 0
                    ),
                }
            )

        result["summary"] = {
            "total_caches": result["total_caches"],
            "corrupted_caches": result["corrupted_caches"],
            "healthy_rate": (result["total_caches"] - result["corrupted_caches"])
            / max(1, result["total_caches"]),
        }

        return result

    # =========================================================================
    # 편의 메서드
    # =========================================================================

    def quick_check(self, addr: int) -> str:
        """
        빠른 상태 확인.

        Args:
            addr: 확인할 주소

        Returns:
            상태 문자열 (ok/warning/error)
        """
        # SLUB 확인
        cache_info = self._slub.find_owning_cache(addr)
        if cache_info is None:
            return "unknown"

        cache, slab, aligned_obj, idx = cache_info
        is_free = self._slub.is_object_free(slab, aligned_obj)

        # KASAN 확인
        if self.kasan_enabled and self._kasan:
            mem_tag = self._kasan.get_mem_tag(self._kasan.reset_tag(addr))

            if is_free and mem_tag != self._kasan.TAG_INVALID:
                return "error"  # 불일치
            if not is_free and mem_tag == self._kasan.TAG_INVALID:
                return "error"  # 불일치
            if mem_tag == self._kasan.TAG_INVALID:
                return "warning"  # freed

        if is_free:
            return "warning"

        return "ok"
