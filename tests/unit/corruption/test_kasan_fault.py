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


# =============================================================================
# analyze_redzone 테스트
# =============================================================================


class TestKasanFaultAnalyzerRedzone:
    """analyze_redzone 테스트."""

    def test_analyze_redzone_valid(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """정상 redzone."""
        base = setup_shadow_tags["base"]
        # Object 1 (64 bytes)의 redzone 검사
        result = kasan_fault_analyzer.analyze_redzone(base, 64)

        assert result["valid"] is True
        assert result["corruption_type"] is None
        assert result["corrupted_granules"] == 0

    def test_analyze_redzone_overflow(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Redzone overflow 탐지."""
        base = setup_shadow_tags["base"]

        # Object 끝 뒤에 object 태그가 확장된 경우 (overflow 시뮬레이션)
        kasan_mock_backend.set_shadow_tag(base + 64, 0x42)  # redzone에 object 태그

        result = kasan_fault_analyzer.analyze_redzone(base, 64)

        assert result["valid"] is False
        assert result["corruption_type"] == "overflow"
        assert result["corrupted_granules"] > 0


# =============================================================================
# build_corruption_timeline 테스트
# =============================================================================


class TestKasanFaultAnalyzerTimeline:
    """build_corruption_timeline 테스트."""

    def test_timeline_freed_memory(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Freed 메모리 타임라인."""
        base = setup_shadow_tags["base"]
        freed_addr = base + 144

        result = kasan_fault_analyzer.build_corruption_timeline(freed_addr)

        assert result["current_state"] == "freed"
        assert result["current_tag"] == 0xFE
        assert "timeline" in result

    def test_timeline_allocated_memory(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Allocated 메모리 타임라인."""
        base = setup_shadow_tags["base"]

        result = kasan_fault_analyzer.build_corruption_timeline(base)

        assert result["current_state"] == "allocated"
        assert result["current_tag"] == 0x42


# =============================================================================
# detect_spray_corruption 테스트
# =============================================================================


class TestKasanFaultAnalyzerSpray:
    """detect_spray_corruption 테스트."""

    def test_detect_normal_region(
        self, kasan_fault_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """정상 영역 스캔."""
        base = setup_shadow_tags["base"]

        result = kasan_fault_analyzer.detect_spray_corruption(base, 256)

        assert result["total_granules"] > 0
        assert "tag_distribution" in result
        assert "anomalies" in result
        assert result["corruption_indicators"]["checked"] is True

    def test_detect_mass_free(self, kasan_fault_analyzer, kasan_mock_backend):
        """대량 해제 탐지."""
        base = 0xFFFF_8882_0000_0000

        # 256 bytes (16 granules)의 연속된 freed 영역
        kasan_mock_backend.set_shadow_tags_range(base, 256, 0xFE)

        result = kasan_fault_analyzer.detect_spray_corruption(base, 256)

        # Mass free anomaly 탐지
        assert result["corruption_indicators"]["has_mass_free"] is True
        mass_free = [a for a in result["anomalies"] if a["type"] == "mass_free"]
        assert len(mass_free) > 0

    def test_detect_heap_spray(self, kasan_fault_analyzer, kasan_mock_backend):
        """Heap spray 패턴 탐지."""
        base = 0xFFFF_8883_0000_0000

        # 동일 태그로 채워진 영역 (90% 이상)
        kasan_mock_backend.set_shadow_tags_range(base, 512, 0x42)

        result = kasan_fault_analyzer.detect_spray_corruption(base, 512)

        # Heap spray anomaly 탐지
        assert result["corruption_indicators"]["has_heap_spray"] is True
        spray = [a for a in result["anomalies"] if a["type"] == "heap_spray"]
        assert len(spray) > 0
