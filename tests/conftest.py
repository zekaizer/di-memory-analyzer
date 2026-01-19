"""pytest fixtures."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


# =============================================================================
# Mock Structures
# =============================================================================


class MockAtomicT(ctypes.Structure):
    """Mock atomic_t 구조체."""

    _fields_ = [("counter", ctypes.c_int)]


class MockPage(ctypes.Structure):
    """Mock struct page."""

    _fields_ = [
        ("flags", ctypes.c_ulong),
        ("compound_head", ctypes.c_ulong),
        ("compound_order", ctypes.c_ubyte),
        ("_refcount", MockAtomicT),
        ("_mapcount", MockAtomicT),
    ]


# =============================================================================
# Mock Backend
# =============================================================================


class MockDIBackend:
    """DIBackend Mock 구현."""

    def __init__(self) -> None:
        self._structs: dict[str, tuple[int, dict[str, int]]] = {}
        self._symbols: dict[str, int] = {}
        self._enums: dict[str, dict[str, int]] = {}
        self._configs: dict[str, bool | int | str] = {}
        self._memory: dict[int, bytes] = {}
        self._pages: dict[int, MockPage] = {}

        # 기본 설정
        self._setup_defaults()

    def _setup_defaults(self) -> None:
        """기본값 설정."""
        # PAGE_SHIFT 설정
        self._configs["CONFIG_PAGE_SHIFT"] = 12

        # pageflags enum 설정
        self._enums["pageflags"] = {
            "PG_locked": 0,
            "PG_writeback": 1,
            "PG_referenced": 2,
            "PG_uptodate": 3,
            "PG_dirty": 4,
            "PG_lru": 5,
            "PG_head": 6,
            "PG_waiters": 7,
            "PG_active": 8,
            "PG_workingset": 9,
            "PG_slab": 10,
            "PG_private": 11,
            "PG_reclaim": 12,
            "PG_swapbacked": 13,
            "PG_unevictable": 14,
            "PG_mlocked": 15,
            "PG_hwpoison": 20,
            "PG_reserved": 25,
            "PG_buddy": 26,
        }

        # struct page 등록
        self._structs["struct page"] = (
            ctypes.sizeof(MockPage),
            {
                "flags": 0,
                "compound_head": 8,
                "compound_order": 16,
                "_refcount": 20,
                "_mapcount": 24,
            },
        )

        # 기본 심볼
        self._symbols["vmemmap"] = 0xFFFF_EA00_0000_0000
        self._symbols["max_pfn"] = 0xFFFF_FFFF_8100_0000

        # vmemmap 포인터 값 설정
        self._memory[0xFFFF_EA00_0000_0000] = (0xFFFF_EA00_0000_0000).to_bytes(
            8, "little"
        )
        # max_pfn 값 설정 (예: 0x100000 = 1M pages)
        self._memory[0xFFFF_FFFF_8100_0000] = (0x100000).to_bytes(8, "little")

    # =========================================================================
    # Structure 메타정보
    # =========================================================================

    def sizeof(self, type_name: str) -> int:
        if type_name not in self._structs:
            raise KeyError(f"Unknown type: {type_name}")
        return self._structs[type_name][0]

    def offsetof(self, struct_name: str, member: str) -> int:
        if struct_name not in self._structs:
            raise KeyError(f"Unknown struct: {struct_name}")
        members = self._structs[struct_name][1]
        if member not in members:
            raise KeyError(f"Unknown member: {struct_name}.{member}")
        return members[member]

    def has_member(self, struct_name: str, member: str) -> bool:
        if struct_name not in self._structs:
            return False
        return member in self._structs[struct_name][1]

    # =========================================================================
    # Memory 읽기
    # =========================================================================

    def read_type(
        self, addr: int | str, type_name: str | None = None
    ) -> ctypes.Structure | int:
        original_addr = addr
        if isinstance(addr, str):
            resolved = self._symbols.get(addr)
            if resolved is None:
                raise KeyError(f"Unknown symbol: {addr}")
            original_addr = resolved

        if type_name == "struct page":
            # 페이지 캐시에서 찾기
            if original_addr in self._pages:
                page = self._pages[original_addr]
                page._base = original_addr
                return page
            # 새 페이지 생성
            page = MockPage()
            page._base = original_addr
            self._pages[original_addr] = page
            return page

        return 0

    def read_u8(self, addr: int | str) -> int:
        return self._read_int(addr, 1)

    def read_u16(self, addr: int | str) -> int:
        return self._read_int(addr, 2)

    def read_u32(self, addr: int | str) -> int:
        return self._read_int(addr, 4)

    def read_u64(self, addr: int | str) -> int:
        return self._read_int(addr, 8)

    def read_bytes(self, addr: int | str, size: int) -> bytes:
        if isinstance(addr, str):
            resolved = self._symbols.get(addr)
            if resolved is None:
                raise KeyError(f"Unknown symbol: {addr}")
            addr = resolved
        return self._memory.get(addr, b"\x00" * size)[:size]

    def read_pointer(self, addr: int | str) -> int:
        return self.read_u64(addr)

    def read_string(self, addr: int | str, max_len: int = 256) -> str:
        data = self.read_bytes(addr, max_len)
        null_idx = data.find(b"\x00")
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode("utf-8", errors="replace")

    def _read_int(self, addr: int | str, size: int) -> int:
        data = self.read_bytes(addr, size)
        return int.from_bytes(data, "little")

    # =========================================================================
    # Symbol
    # =========================================================================

    def symbol_to_addr(self, name: str) -> int | None:
        return self._symbols.get(name)

    def addr_to_symbol(self, addr: int) -> tuple[str, int] | None:
        # 간단한 구현: 정확히 일치하는 심볼만 반환
        for name, sym_addr in self._symbols.items():
            if sym_addr <= addr < sym_addr + 0x1000:
                return (name, addr - sym_addr)
        return None

    def is_symbol_valid(self, name: str) -> bool:
        return name in self._symbols

    # =========================================================================
    # Kernel Config
    # =========================================================================

    def get_enum(self, enum_name: str) -> dict[str, int] | None:
        return self._enums.get(enum_name)

    def get_enum_value(self, enum_name: str, member: str) -> int | None:
        enum = self._enums.get(enum_name)
        if enum is None:
            return None
        return enum.get(member)

    def get_config(self, config_name: str) -> bool | int | str | None:
        return self._configs.get(config_name)

    # =========================================================================
    # 주소 변환
    # =========================================================================

    def virt_to_phys(self, vaddr: int) -> int | None:
        # 간단한 구현: 상위 비트 제거
        if vaddr >= 0xFFFF_8000_0000_0000:
            return vaddr - 0xFFFF_8000_0000_0000
        return None

    def phys_to_virt(self, paddr: int) -> int:
        return paddr + 0xFFFF_8000_0000_0000

    # =========================================================================
    # Per-CPU
    # =========================================================================

    def per_cpu(self, symbol: str, cpu_id: int) -> int:
        base = self._symbols.get(symbol, 0)
        return base + cpu_id * 0x1000

    # =========================================================================
    # Container
    # =========================================================================

    def container_of(self, addr: int, struct_name: str, member: str) -> int:
        offset = self.offsetof(struct_name, member)
        return addr - offset

    # =========================================================================
    # 테스트 헬퍼
    # =========================================================================

    def register_page(self, pfn: int, flags: int = 0, **kwargs) -> MockPage:
        """테스트용 페이지 등록."""
        vmemmap_base = 0xFFFF_EA00_0000_0000
        page_size = ctypes.sizeof(MockPage)
        page_addr = vmemmap_base + pfn * page_size

        page = MockPage()
        page.flags = flags
        page.compound_head = kwargs.get("compound_head", 0)
        page.compound_order = kwargs.get("compound_order", 0)
        page._refcount.counter = kwargs.get("refcount", 1)
        page._mapcount.counter = kwargs.get("mapcount", 0)

        self._pages[page_addr] = page
        return page


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_backend() -> MockDIBackend:
    """Mock backend fixture."""
    return MockDIBackend()


@pytest.fixture
def struct_helper(mock_backend: MockDIBackend):
    """StructHelper fixture."""
    from di_memory.core.struct_helper import StructHelper

    return StructHelper(mock_backend)


@pytest.fixture
def address_translator(mock_backend: MockDIBackend):
    """AddressTranslator fixture."""
    from di_memory.core.address_translator import AddressTranslator

    return AddressTranslator(mock_backend)


@pytest.fixture
def kernel_resolver(mock_backend: MockDIBackend):
    """KernelResolver fixture."""
    from di_memory.core.kernel_resolver import KernelResolver

    return KernelResolver(mock_backend)


@pytest.fixture
def page_analyzer(
    mock_backend: MockDIBackend,
    struct_helper,
    address_translator,
    kernel_resolver,
):
    """PageAnalyzer fixture."""
    from di_memory.analyzers.page import PageAnalyzer

    return PageAnalyzer(
        backend=mock_backend,
        structs=struct_helper,
        addr=address_translator,
        symbols=kernel_resolver,
    )


@pytest.fixture
def page_flags_helper(kernel_resolver):
    """PageFlagsHelper fixture."""
    from di_memory.utils.flags import PageFlagsHelper

    return PageFlagsHelper(kernel_resolver)
