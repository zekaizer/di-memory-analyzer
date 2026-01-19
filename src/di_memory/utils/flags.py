"""Page/Slab 플래그 헬퍼.

플래그 비트 위치는 KernelResolver를 통해 런타임에 조회.
이 모듈은 플래그 이름 상수와 디코딩 유틸리티만 제공.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from di_memory.utils.constants import PAGEFLAGS_ENUM

if TYPE_CHECKING:
    from di_memory.core.kernel_resolver import KernelResolver

# =============================================================================
# 플래그 이름 상수 (비트 위치는 런타임 조회)
# =============================================================================

PG_LOCKED = "PG_locked"
PG_WRITEBACK = "PG_writeback"
PG_REFERENCED = "PG_referenced"
PG_UPTODATE = "PG_uptodate"
PG_DIRTY = "PG_dirty"
PG_LRU = "PG_lru"
PG_HEAD = "PG_head"
PG_WAITERS = "PG_waiters"
PG_ACTIVE = "PG_active"
PG_WORKINGSET = "PG_workingset"
PG_SLAB = "PG_slab"
PG_PRIVATE = "PG_private"
PG_RECLAIM = "PG_reclaim"
PG_SWAPBACKED = "PG_swapbacked"
PG_UNEVICTABLE = "PG_unevictable"
PG_MLOCKED = "PG_mlocked"
PG_HWPOISON = "PG_hwpoison"
PG_RESERVED = "PG_reserved"
PG_BUDDY = "PG_buddy"


class PageFlagsHelper:
    """Page flags 런타임 디코딩."""

    def __init__(self, resolver: KernelResolver) -> None:
        self._resolver = resolver
        self._flags_map: dict[str, int] | None = None

    def _load_flags(self) -> dict[str, int]:
        """Enum에서 플래그 매핑 로드 (캐싱)."""
        if self._flags_map is None:
            self._flags_map = self._resolver.get_enum(PAGEFLAGS_ENUM) or {}
        return self._flags_map

    def get_bit(self, flag_name: str) -> int | None:
        """
        플래그 비트 위치 조회.

        Args:
            flag_name: 플래그 이름 (예: "PG_slab")

        Returns:
            비트 위치 또는 None
        """
        return self._load_flags().get(flag_name)

    def test_flag(self, flags: int, flag_name: str) -> bool:
        """
        플래그 설정 여부 확인.

        Args:
            flags: 플래그 raw 값
            flag_name: 플래그 이름

        Returns:
            설정 여부
        """
        bit = self.get_bit(flag_name)
        if bit is None:
            return False
        return bool(flags & (1 << bit))

    def decode(self, flags: int) -> list[str]:
        """
        설정된 플래그 이름 리스트 반환.

        Args:
            flags: 플래그 raw 값

        Returns:
            설정된 플래그 이름 리스트
        """
        result = []
        for name, bit in self._load_flags().items():
            if flags & (1 << bit):
                result.append(name)
        return result
