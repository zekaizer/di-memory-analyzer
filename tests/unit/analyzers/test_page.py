"""PageAnalyzer 테스트."""

from di_memory.analyzers.page import PageAnalyzer
from di_memory.utils.flags import (
    PG_LOCKED,
    PG_SLAB,
)
from tests.conftest import MockDIBackend


class TestPageAnalyzerProperties:
    """PageAnalyzer 속성 테스트."""

    def test_page_shift(self, page_analyzer: PageAnalyzer) -> None:
        """PAGE_SHIFT 값."""
        assert page_analyzer.page_shift == 12

    def test_page_size(self, page_analyzer: PageAnalyzer) -> None:
        """PAGE_SIZE 값."""
        assert page_analyzer.page_size == 4096


class TestPageAnalyzerLookup:
    """PageAnalyzer 페이지 조회 테스트."""

    def test_get_page(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """PFN으로 페이지 조회."""
        mock_backend.register_page(100, flags=0)

        page = page_analyzer.get_page(100)

        assert page is not None

    def test_get_page_invalid_pfn(self, page_analyzer: PageAnalyzer) -> None:
        """유효하지 않은 PFN."""
        page = page_analyzer.get_page(-1)

        assert page is None

    def test_get_page_by_vaddr(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """가상 주소로 페이지 조회."""
        # vaddr = 0xFFFF_8000_0000_0000 + 0x100000 (PFN 256)
        vaddr = 0xFFFF_8000_0010_0000
        mock_backend.register_page(256, flags=0)

        page = page_analyzer.get_page_by_vaddr(vaddr)

        assert page is not None


class TestPageAnalyzerFlags:
    """PageAnalyzer 플래그 테스트."""

    def test_get_flags(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """플래그 raw 값 조회."""
        flags = 1 << 10  # PG_slab
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)
        result = page_analyzer.get_flags(page)

        assert result == flags

    def test_decode_flags(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """플래그 디코딩."""
        flags = (1 << 0) | (1 << 10)  # locked | slab
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)
        result = page_analyzer.decode_flags(page.flags)

        assert PG_LOCKED in result
        assert PG_SLAB in result

    def test_test_flag(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """특정 플래그 테스트."""
        flags = 1 << 10  # PG_slab
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.test_flag(page, PG_SLAB) is True
        assert page_analyzer.test_flag(page, PG_LOCKED) is False


class TestPageAnalyzerTypes:
    """PageAnalyzer 페이지 타입 판별 테스트."""

    def test_is_slab_page(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """SLUB 페이지 여부."""
        flags = 1 << 10  # PG_slab
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_slab_page(page) is True

    def test_is_slab_page_false(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """SLUB 페이지가 아닌 경우."""
        mock_backend.register_page(100, flags=0)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_slab_page(page) is False

    def test_is_head_page(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Head page 여부."""
        flags = 1 << 6  # PG_head
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_head_page(page) is True

    def test_is_compound_page_head(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Compound page (head) 여부."""
        flags = 1 << 6  # PG_head
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_compound_page(page) is True

    def test_is_buddy_page(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Buddy page 여부."""
        flags = 1 << 26  # PG_buddy
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_buddy_page(page) is True

    def test_is_reserved(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Reserved page 여부."""
        flags = 1 << 25  # PG_reserved
        mock_backend.register_page(100, flags=flags)

        page = page_analyzer.get_page(100)

        assert page_analyzer.is_reserved(page) is True


class TestPageAnalyzerRefcount:
    """PageAnalyzer refcount 테스트."""

    def test_get_refcount(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Reference count 조회."""
        mock_backend.register_page(100, refcount=5)

        page = page_analyzer.get_page(100)

        assert page_analyzer.get_refcount(page) == 5

    def test_get_mapcount(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """Map count 조회."""
        mock_backend.register_page(100, mapcount=3)

        page = page_analyzer.get_page(100)

        assert page_analyzer.get_mapcount(page) == 3


class TestPageAnalyzerAddress:
    """PageAnalyzer 주소 유틸 테스트."""

    def test_page_to_pfn(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """struct page 주소를 PFN으로 변환."""
        # vmemmap_base + pfn * sizeof(struct page)
        import ctypes

        from tests.conftest import MockPage

        vmemmap_base = 0xFFFF_EA00_0000_0000
        page_size = ctypes.sizeof(MockPage)
        page_addr = vmemmap_base + 100 * page_size

        pfn = page_analyzer.page_to_pfn(page_addr)

        assert pfn == 100

    def test_get_page_aligned(self, page_analyzer: PageAnalyzer) -> None:
        """페이지 정렬."""
        addr = 0x12345678

        aligned = page_analyzer.get_page_aligned(addr)

        assert aligned == 0x12345000

    def test_get_page_offset(self, page_analyzer: PageAnalyzer) -> None:
        """페이지 내 오프셋."""
        addr = 0x12345678

        offset = page_analyzer.get_page_offset(addr)

        assert offset == 0x678


class TestPageAnalyzerIteration:
    """PageAnalyzer 순회 테스트."""

    def test_iter_pfn_range(
        self, page_analyzer: PageAnalyzer, mock_backend: MockDIBackend
    ) -> None:
        """PFN 범위 순회."""
        for pfn in range(10, 15):
            mock_backend.register_page(pfn, flags=0)

        result = list(page_analyzer.iter_pfn_range(10, 15))

        assert len(result) == 5
        assert all(isinstance(item, tuple) for item in result)
        assert [pfn for pfn, _ in result] == list(range(10, 15))
