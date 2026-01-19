"""주소 변환 및 PFN 관련 기능."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend

# 기본값 (CONFIG_PAGE_SHIFT를 가져올 수 없는 경우)
DEFAULT_PAGE_SHIFT = 12


class AddressTranslator:
    """주소 변환 및 PFN 관련 기능 제공."""

    def __init__(self, backend: DIBackend) -> None:
        self._backend = backend
        self._vmemmap_base: int | None = None
        self._page_struct_size: int | None = None
        self._page_shift: int | None = None
        self._max_pfn: int | None = None

    # =========================================================================
    # VA <-> PA
    # =========================================================================

    def virt_to_phys(self, vaddr: int) -> int | None:
        """가상 주소를 물리 주소로 변환."""
        return self._backend.virt_to_phys(vaddr)

    def phys_to_virt(self, paddr: int) -> int:
        """물리 주소를 가상 주소로 변환."""
        return self._backend.phys_to_virt(paddr)

    # =========================================================================
    # PFN 변환
    # =========================================================================

    def pfn_to_phys(self, pfn: int) -> int:
        """PFN을 물리 주소로 변환."""
        return pfn << self._get_page_shift()

    def phys_to_pfn(self, paddr: int) -> int:
        """물리 주소를 PFN으로 변환."""
        return paddr >> self._get_page_shift()

    def pfn_to_page(self, pfn: int) -> ctypes.Structure:
        """
        PFN을 struct page 주소로 변환하고 읽어 반환.

        Linux 커널의 vmemmap 모델 기준:
        page = vmemmap_base + pfn * sizeof(struct page)

        반환된 구조체에는 ._base 속성으로 원본 주소가 저장됨.
        """
        vmemmap_base = self._get_vmemmap_base()
        page_size = self._get_page_struct_size()
        page_addr = vmemmap_base + pfn * page_size
        page = self._backend.read_type(page_addr, "struct page")
        page._base = page_addr
        return page

    def page_to_pfn(self, page_addr: int) -> int:
        """
        struct page 주소를 PFN으로 변환.

        pfn = (page_addr - vmemmap_base) / sizeof(struct page)
        """
        vmemmap_base = self._get_vmemmap_base()
        page_size = self._get_page_struct_size()
        return (page_addr - vmemmap_base) // page_size

    def virt_to_page(self, vaddr: int) -> ctypes.Structure | None:
        """
        가상 주소를 struct page로 변환.

        반환된 구조체에는 ._base 속성으로 원본 주소가 저장됨.
        """
        paddr = self.virt_to_phys(vaddr)
        if paddr is None:
            return None
        pfn = self.phys_to_pfn(paddr)
        return self.pfn_to_page(pfn)

    # =========================================================================
    # Page 관련 상수 (Properties)
    # =========================================================================

    @property
    def page_shift(self) -> int:
        """PAGE_SHIFT (CONFIG_PAGE_SHIFT, 기본값 12)."""
        return self._get_page_shift()

    @property
    def page_size(self) -> int:
        """PAGE_SIZE (1 << PAGE_SHIFT)."""
        return 1 << self.page_shift

    @property
    def page_mask(self) -> int:
        """PAGE_MASK (~(PAGE_SIZE - 1))."""
        return ~(self.page_size - 1)

    # =========================================================================
    # 유효성 검사
    # =========================================================================

    def is_valid_vaddr(self, vaddr: int) -> bool:
        """가상 주소가 유효한지 확인."""
        return self.virt_to_phys(vaddr) is not None

    def is_valid_pfn(self, pfn: int) -> bool:
        """PFN이 유효한지 확인."""
        if pfn < 0:
            return False
        max_pfn = self._get_max_pfn()
        return max_pfn is None or pfn < max_pfn

    # =========================================================================
    # Private
    # =========================================================================

    def _get_vmemmap_base(self) -> int:
        """vmemmap_base 심볼 주소를 캐싱하여 반환."""
        if self._vmemmap_base is None:
            addr = self._backend.symbol_to_addr("vmemmap")
            if addr is None:
                # vmemmap 심볼이 없으면 vmemmap_base 시도
                addr = self._backend.symbol_to_addr("vmemmap_base")
            if addr is None:
                raise ValueError("vmemmap symbol not found")
            # vmemmap은 포인터이므로 값을 읽어야 함
            self._vmemmap_base = self._backend.read_pointer(addr)
        return self._vmemmap_base

    def _get_page_struct_size(self) -> int:
        """struct page 크기를 캐싱하여 반환."""
        if self._page_struct_size is None:
            self._page_struct_size = self._backend.sizeof("struct page")
        return self._page_struct_size

    def _get_page_shift(self) -> int:
        """PAGE_SHIFT를 캐싱하여 반환."""
        if self._page_shift is None:
            config_value = self._backend.get_config("CONFIG_PAGE_SHIFT")
            if isinstance(config_value, int):
                self._page_shift = config_value
            else:
                self._page_shift = DEFAULT_PAGE_SHIFT
        return self._page_shift

    def _get_max_pfn(self) -> int | None:
        """max_pfn을 캐싱하여 반환."""
        if self._max_pfn is None:
            addr = self._backend.symbol_to_addr("max_pfn")
            if addr is not None:
                self._max_pfn = self._backend.read_pointer(addr)
        return self._max_pfn
