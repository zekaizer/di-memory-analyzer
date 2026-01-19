"""Page 서브시스템 분석기."""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from typing import TYPE_CHECKING

from di_memory.analyzers.base import BaseAnalyzer
from di_memory.utils.flags import (
    PG_BUDDY,
    PG_HEAD,
    PG_RESERVED,
    PG_SLAB,
    PageFlagsHelper,
)

if TYPE_CHECKING:
    from di_memory.backend.protocol import DIBackend
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper


class PageAnalyzer(BaseAnalyzer):
    """Page 서브시스템 분석기."""

    def __init__(
        self,
        backend: DIBackend,
        structs: StructHelper,
        addr: AddressTranslator,
        symbols: KernelResolver,
    ) -> None:
        """
        PageAnalyzer 초기화.

        Args:
            backend: DIBackend 인스턴스
            structs: StructHelper 인스턴스
            addr: AddressTranslator 인스턴스
            symbols: KernelResolver 인스턴스
        """
        super().__init__(backend, structs, addr, symbols)
        self._flags = PageFlagsHelper(symbols)

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def page_shift(self) -> int:
        """PAGE_SHIFT 값."""
        return self._addr.page_shift

    @property
    def page_size(self) -> int:
        """PAGE_SIZE 값."""
        return self._addr.page_size

    # =========================================================================
    # Page 조회
    # =========================================================================

    def get_page(self, pfn: int) -> ctypes.Structure | None:
        """
        PFN으로 struct page 조회.

        Args:
            pfn: Page Frame Number

        Returns:
            struct page 또는 None (유효하지 않은 PFN)
        """
        if not self._addr.is_valid_pfn(pfn):
            return None
        return self._addr.pfn_to_page(pfn)

    def get_page_by_vaddr(self, vaddr: int) -> ctypes.Structure | None:
        """
        Virtual address로 struct page 조회.

        Args:
            vaddr: 가상 주소

        Returns:
            struct page 또는 None
        """
        return self._addr.virt_to_page(vaddr)

    # =========================================================================
    # Flags
    # =========================================================================

    def get_flags(self, page: ctypes.Structure) -> int:
        """
        페이지 플래그 raw 값.

        Args:
            page: struct page

        Returns:
            플래그 raw 값
        """
        return page.flags

    def decode_flags(self, flags: int) -> list[str]:
        """
        플래그를 이름 리스트로 변환.

        Args:
            flags: 플래그 raw 값

        Returns:
            설정된 플래그 이름 리스트
        """
        return self._flags.decode(flags)

    def test_flag(self, page: ctypes.Structure, flag_name: str) -> bool:
        """
        특정 플래그 설정 여부.

        Args:
            page: struct page
            flag_name: 플래그 이름 (예: "PG_slab")

        Returns:
            플래그 설정 여부
        """
        return self._flags.test_flag(page.flags, flag_name)

    # =========================================================================
    # Page 타입 판별
    # =========================================================================

    def is_slab_page(self, page: ctypes.Structure) -> bool:
        """
        SLUB allocator 관리 페이지 여부.

        Args:
            page: struct page

        Returns:
            SLUB 페이지 여부
        """
        return self._flags.test_flag(page.flags, PG_SLAB)

    def is_compound_page(self, page: ctypes.Structure) -> bool:
        """
        Compound page (huge page 등) 여부.

        Args:
            page: struct page

        Returns:
            Compound page 여부
        """
        if self._flags.test_flag(page.flags, PG_HEAD):
            return True
        return self._is_tail_page(page)

    def is_head_page(self, page: ctypes.Structure) -> bool:
        """
        Compound head page 여부.

        Args:
            page: struct page

        Returns:
            Head page 여부
        """
        return self._flags.test_flag(page.flags, PG_HEAD)

    def is_buddy_page(self, page: ctypes.Structure) -> bool:
        """
        Buddy allocator 관리 페이지 여부.

        Args:
            page: struct page

        Returns:
            Buddy 페이지 여부
        """
        return self._flags.test_flag(page.flags, PG_BUDDY)

    def is_reserved(self, page: ctypes.Structure) -> bool:
        """
        시스템 예약 페이지 여부.

        Args:
            page: struct page

        Returns:
            예약 페이지 여부
        """
        return self._flags.test_flag(page.flags, PG_RESERVED)

    # =========================================================================
    # Compound Page
    # =========================================================================

    def get_compound_head(self, page: ctypes.Structure) -> ctypes.Structure:
        """
        Compound page의 head page 반환.

        Args:
            page: struct page (head 또는 tail)

        Returns:
            head page의 struct page
        """
        if self._flags.test_flag(page.flags, PG_HEAD):
            return page
        # tail page: compound_head 포인터 따라감 (LSB 마스킹)
        head_addr = page.compound_head & ~1
        return self._structs.read(head_addr, "struct page")

    def get_compound_order(self, page: ctypes.Structure) -> int:
        """
        Compound page의 order (2^order pages).

        Args:
            page: struct page

        Returns:
            order 값
        """
        head = self.get_compound_head(page)
        # compound_order 위치는 커널 버전에 따라 다름
        if self._structs.has_member("struct page", "compound_order"):
            return head.compound_order
        # 구버전: first tail page에 저장
        head_pfn = self._addr.page_to_pfn(head)
        first_tail = self._addr.pfn_to_page(head_pfn + 1)
        return first_tail.compound_order

    # =========================================================================
    # Refcount
    # =========================================================================

    def get_refcount(self, page: ctypes.Structure) -> int:
        """
        Page reference count.

        Args:
            page: struct page

        Returns:
            reference count 값
        """
        return page._refcount.counter

    def get_mapcount(self, page: ctypes.Structure) -> int:
        """
        페이지가 매핑된 프로세스 수.

        Args:
            page: struct page

        Returns:
            map count 값
        """
        return page._mapcount.counter

    # =========================================================================
    # 주소 유틸
    # =========================================================================

    def page_to_virt(self, page: ctypes.Structure) -> int:
        """
        struct page를 가상 주소로 변환.

        Args:
            page: struct page

        Returns:
            가상 주소
        """
        pfn = self._addr.page_to_pfn(page)
        paddr = self._addr.pfn_to_phys(pfn)
        return self._addr.phys_to_virt(paddr)

    def page_to_pfn(self, page: ctypes.Structure) -> int:
        """
        struct page를 PFN으로 변환.

        Args:
            page: struct page

        Returns:
            PFN
        """
        return self._addr.page_to_pfn(page)

    def get_page_aligned(self, addr: int) -> int:
        """
        주소를 페이지 경계로 정렬.

        Args:
            addr: 메모리 주소

        Returns:
            페이지 정렬된 주소
        """
        return addr & self._addr.page_mask

    def get_page_offset(self, addr: int) -> int:
        """
        페이지 내 오프셋.

        Args:
            addr: 메모리 주소

        Returns:
            페이지 내 오프셋
        """
        return addr & (self._addr.page_size - 1)

    # =========================================================================
    # 순회
    # =========================================================================

    def iter_pfn_range(
        self, start_pfn: int, end_pfn: int
    ) -> Iterator[tuple[int, ctypes.Structure]]:
        """
        PFN 범위 순회.

        Args:
            start_pfn: 시작 PFN (포함)
            end_pfn: 끝 PFN (미포함)

        Yields:
            (pfn, struct page) 튜플
        """
        for pfn in range(start_pfn, end_pfn):
            page = self.get_page(pfn)
            if page:
                yield pfn, page

    # =========================================================================
    # Private
    # =========================================================================

    def _is_tail_page(self, page: ctypes.Structure) -> bool:
        """Tail page 여부 (compound_head의 LSB로 판별)."""
        if not self._structs.has_member("struct page", "compound_head"):
            return False
        return bool(page.compound_head & 1)
