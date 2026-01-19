"""CorruptionDetector 테스트."""

from __future__ import annotations

import pytest

from tests.conftest import MockDIBackend


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def corruption_detector(kasan_mock_backend: MockDIBackend):
    """CorruptionDetector fixture (KASAN 없음)."""
    from di_memory.analyzers.slub import SlubAnalyzer
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper
    from di_memory.corruption.detector import CorruptionDetector

    structs = StructHelper(kasan_mock_backend)
    addr = AddressTranslator(kasan_mock_backend)
    symbols = KernelResolver(kasan_mock_backend)

    slub = SlubAnalyzer(
        backend=kasan_mock_backend,
        structs=structs,
        addr=addr,
        symbols=symbols,
    )

    return CorruptionDetector(slub=slub, kasan=None)


@pytest.fixture
def corruption_detector_with_kasan(kasan_mock_backend: MockDIBackend):
    """CorruptionDetector fixture (KASAN 포함)."""
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.analyzers.slub import SlubAnalyzer
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper
    from di_memory.corruption.detector import CorruptionDetector

    structs = StructHelper(kasan_mock_backend)
    addr = AddressTranslator(kasan_mock_backend)
    symbols = KernelResolver(kasan_mock_backend)

    slub = SlubAnalyzer(
        backend=kasan_mock_backend,
        structs=structs,
        addr=addr,
        symbols=symbols,
    )

    kasan = KasanAnalyzer(
        backend=kasan_mock_backend,
        structs=structs,
        addr=addr,
        symbols=symbols,
    )

    return CorruptionDetector(slub=slub, kasan=kasan)


# =============================================================================
# 기본 테스트
# =============================================================================


class TestCorruptionDetectorBasic:
    """CorruptionDetector 기본 테스트."""

    def test_init_without_kasan(self, corruption_detector):
        """KASAN 없이 초기화."""
        assert corruption_detector._slub is not None
        assert corruption_detector._kasan is None
        assert corruption_detector._kasan_fault is None

    def test_init_with_kasan(self, corruption_detector_with_kasan):
        """KASAN과 함께 초기화."""
        assert corruption_detector_with_kasan._slub is not None
        assert corruption_detector_with_kasan._kasan is not None
        assert corruption_detector_with_kasan._kasan_fault is not None

    def test_kasan_enabled_property(
        self, corruption_detector, corruption_detector_with_kasan
    ):
        """kasan_enabled 프로퍼티."""
        assert not corruption_detector.kasan_enabled
        assert corruption_detector_with_kasan.kasan_enabled


# =============================================================================
# analyze_corruption 테스트
# =============================================================================


class TestCorruptionDetectorAnalyze:
    """analyze_corruption 테스트."""

    def test_analyze_unknown_addr(self, corruption_detector_with_kasan):
        """알 수 없는 주소 분석."""
        result = corruption_detector_with_kasan.analyze_corruption(0xDEAD_BEEF)

        assert "addr" in result
        assert "analyses" in result
        assert "likely_cause" in result
        assert "severity" in result


# =============================================================================
# quick_check 테스트
# =============================================================================


class TestCorruptionDetectorQuickCheck:
    """quick_check 테스트."""

    def test_quick_check_unknown(self, corruption_detector_with_kasan):
        """알 수 없는 주소."""
        result = corruption_detector_with_kasan.quick_check(0xDEAD_BEEF)
        assert result == "unknown"
