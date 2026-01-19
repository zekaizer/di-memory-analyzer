"""KasanFaultAnalyzer 테스트."""

from __future__ import annotations

import pytest

from tests.conftest import MockDIBackend

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def setup_shadow_tags(kasan_mock_backend: MockDIBackend):
    """기본 shadow 태그 설정."""
    base_addr = 0xFFFF_8881_0000_0000

    # Object 1: tag 0x42, 64 bytes
    kasan_mock_backend.set_shadow_tags_range(base_addr, 64, 0x42)

    # Redzone: tag 0xFE (invalid), 16 bytes
    kasan_mock_backend.set_shadow_tags_range(base_addr + 64, 16, 0xFE)

    # Object 2: tag 0x43, 64 bytes
    kasan_mock_backend.set_shadow_tags_range(base_addr + 80, 64, 0x43)

    # Freed object: tag 0xFE
    kasan_mock_backend.set_shadow_tags_range(base_addr + 144, 64, 0xFE)

    # Kernel (untagged): tag 0xFF
    kasan_mock_backend.set_shadow_tags_range(base_addr + 208, 64, 0xFF)

    return {
        "base": base_addr,
        "obj1_tag": 0x42,
        "obj2_tag": 0x43,
    }


@pytest.fixture
def kasan_fault_analyzer(kasan_mock_backend: MockDIBackend):
    """KasanFaultAnalyzer fixture."""
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper
    from di_memory.corruption.kasan import KasanFaultAnalyzer

    structs = StructHelper(kasan_mock_backend)
    addr = AddressTranslator(kasan_mock_backend)
    symbols = KernelResolver(kasan_mock_backend)

    kasan = KasanAnalyzer(
        backend=kasan_mock_backend,
        structs=structs,
        addr=addr,
        symbols=symbols,
    )

    return KasanFaultAnalyzer(kasan=kasan, slub=None)


# =============================================================================
# analyze_fault 테스트
# =============================================================================


class TestKasanFaultAnalyzerAnalyzeFault:
    """analyze_fault 테스트."""

    def test_analyze_fault_uaf(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """UAF fault 분석."""
        base = setup_shadow_tags["base"]
        freed_addr = base + 144
        ptr = kasan_fault_analyzer._kasan.set_tag(freed_addr, 0x42)

        result = kasan_fault_analyzer.analyze_fault(ptr, 8)
        assert result["ptr_tag"] == 0x42
        assert result["mem_tag"] == 0xFE
        assert result["bug_type"] == "use-after-free"

    def test_analyze_fault_oob(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """OOB fault 분석 (redzone 접근)."""
        base = setup_shadow_tags["base"]
        # Object 1 끝을 넘어 redzone에 접근
        redzone_addr = base + 64
        ptr = kasan_fault_analyzer._kasan.set_tag(redzone_addr, 0x42)

        result = kasan_fault_analyzer.analyze_fault(ptr, 8)
        assert result["ptr_tag"] == 0x42
        assert result["mem_tag"] == 0xFE
        assert result["bug_type"] == "use-after-free"  # 0xFE는 UAF로 분류

    def test_analyze_fault_tag_mismatch(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Tag mismatch fault 분석."""
        base = setup_shadow_tags["base"]
        # Object 2에 잘못된 태그로 접근
        ptr = kasan_fault_analyzer._kasan.set_tag(base + 80, 0x42)  # 실제는 0x43

        result = kasan_fault_analyzer.analyze_fault(ptr, 8)
        assert result["ptr_tag"] == 0x42
        assert result["mem_tag"] == 0x43
        assert result["bug_type"] == "tag-mismatch"


# =============================================================================
# analyze_uaf 테스트
# =============================================================================


class TestKasanFaultAnalyzerAnalyzeUaf:
    """analyze_uaf 테스트."""

    def test_analyze_uaf_detected(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """UAF 탐지."""
        base = setup_shadow_tags["base"]
        freed_addr = base + 144
        ptr = kasan_fault_analyzer._kasan.set_tag(freed_addr, 0x42)

        result = kasan_fault_analyzer.analyze_uaf(ptr)
        assert result is not None
        assert result["bug_type"] == "use-after-free"
        assert result["mem_tag"] == 0xFE

    def test_analyze_uaf_not_freed(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """정상 메모리는 UAF 아님."""
        base = setup_shadow_tags["base"]
        ptr = kasan_fault_analyzer._kasan.set_tag(base, 0x42)

        result = kasan_fault_analyzer.analyze_uaf(ptr)
        assert result is None


# =============================================================================
# analyze_oob 테스트
# =============================================================================


class TestKasanFaultAnalyzerAnalyzeOob:
    """analyze_oob 테스트."""

    def test_analyze_oob_detected(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """OOB 탐지 (태그 변경 경계)."""
        base = setup_shadow_tags["base"]
        # Object 2(tag 0x43) 영역에 Object 1 태그(0x42)로 접근 -> OOB
        # base + 80은 Object 2 시작 (tag 0x43)
        ptr = kasan_fault_analyzer._kasan.set_tag(base + 80, 0x42)

        result = kasan_fault_analyzer.analyze_oob(ptr, 16)
        assert result is not None
        assert result["bug_type"] == "out-of-bounds"
        assert result["first_bad_tag"] == 0x43

    def test_analyze_oob_valid_access(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """유효한 접근은 OOB 아님."""
        base = setup_shadow_tags["base"]
        ptr = kasan_fault_analyzer._kasan.set_tag(base, 0x42)

        result = kasan_fault_analyzer.analyze_oob(ptr, 32)
        assert result is None


# =============================================================================
# find_nearby_objects 테스트
# =============================================================================


class TestKasanFaultAnalyzerFindNearbyObjects:
    """find_nearby_objects 테스트."""

    def test_find_nearby_objects(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """주변 object 검색."""
        base = setup_shadow_tags["base"]

        # base + 64 근처 검색 (redzone/object 경계)
        objects = kasan_fault_analyzer.find_nearby_objects(base + 64, 128)

        # 태그 변화 지점들이 검색됨
        assert len(objects) > 0
        tags = [obj["tag"] for obj in objects]
        # 0x42 -> 0xFE, 0xFE -> 0x43 등의 경계
        assert any(t in tags for t in [0x42, 0x43, 0xFE])
