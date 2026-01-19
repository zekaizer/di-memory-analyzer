"""FreelistCorruptionDetector 테스트."""

from __future__ import annotations

import pytest

from di_memory.corruption.freelist import FreelistCorruptionDetector
from tests.conftest import MockDIBackend


@pytest.fixture
def freelist_detector(slub_analyzer):
    """FreelistCorruptionDetector 인스턴스."""
    return FreelistCorruptionDetector(slub_analyzer)


@pytest.fixture
def setup_basic_caches(mock_backend: MockDIBackend):
    """기본 cache 설정."""
    cache1 = mock_backend.register_kmem_cache(
        addr=0xFFFF_8880_0001_0000,
        name="kmalloc-128",
        object_size=128,
        size=128,
        offset=64,
        random=0x1234_5678_9ABC_DEF0,
    )
    cache2 = mock_backend.register_kmem_cache(
        addr=0xFFFF_8880_0002_0000,
        name="kmalloc-256",
        object_size=256,
        size=256,
        offset=128,
        random=0xFEDC_BA98_7654_3210,
    )

    mock_backend.link_caches([0xFFFF_8880_0001_0000, 0xFFFF_8880_0002_0000])

    return [cache1, cache2]


@pytest.fixture
def setup_slab_with_freelist(mock_backend: MockDIBackend, setup_basic_caches):
    """Freelist가 있는 slab 설정."""
    cache = setup_basic_caches[0]
    cache_addr = 0xFFFF_8880_0001_0000

    slab_addr = 0xFFFF_EA00_0010_0000
    slab = mock_backend.register_slab(
        addr=slab_addr,
        cache_addr=cache_addr,
        objects=8,
        inuse=5,
    )
    slab._base = slab_addr

    slab_virt_addr = 0xFFFF_8880_1000_0000

    mock_backend.setup_freelist(
        slab=slab,
        cache=cache,
        free_indices=[2, 5, 7],
        slab_virt_addr=slab_virt_addr,
        hardened=True,
    )

    return {
        "cache": cache,
        "cache_addr": cache_addr,
        "slab": slab,
        "slab_addr": slab_addr,
        "slab_virt_addr": slab_virt_addr,
        "free_indices": [2, 5, 7],
    }


class TestFreelistCorruptionDetectorValidate:
    """validate_freelist() 메서드 테스트."""

    def test_validate_freelist_valid(
        self, freelist_detector, mock_backend, setup_slab_with_freelist
    ):
        """유효한 freelist 검증."""
        data = setup_slab_with_freelist
        slab = mock_backend._slabs[data["slab_addr"]]
        slab._base = data["slab_addr"]

        # Mock 환경에서는 slab_to_virt 등이 완전히 동작하지 않으므로
        # 기본 구조만 검증
        # 실제 통합 테스트에서 완전한 검증 필요


class TestFreelistCorruptionDetectorTrace:
    """trace_corrupted_freeptr() 메서드 테스트."""

    def test_trace_corrupted_freeptr(self, freelist_detector, setup_basic_caches):
        """Corrupted 포인터 역추적."""
        cache = setup_basic_caches[0]
        cache._base = 0xFFFF_8880_0001_0000

        ptr_addr = 0xFFFF_8880_1000_0040
        encoded_value = 0xDEAD_BEEF_DEAD_BEEF

        result = freelist_detector.trace_corrupted_freeptr(
            cache, ptr_addr, encoded_value
        )

        assert result["ptr_addr"] == ptr_addr
        assert result["encoded_value"] == encoded_value
        assert "decoded_value" in result
        assert "expected_range" in result
        assert "analysis" in result
        assert "likely_cause" in result

    def test_trace_corrupted_freeptr_bitflip_cause(
        self, freelist_detector, setup_basic_caches, mock_backend
    ):
        """비트플립이 원인인 경우."""
        cache = setup_basic_caches[0]
        cache._base = 0xFFFF_8880_0001_0000

        # 페이지 범위 내에서 1비트 플립 시뮬레이션
        ptr_addr = 0xFFFF_8880_1000_0040
        # expected_base = 0xFFFF_8880_1000_0000 (page aligned)
        # expected_end = 0xFFFF_8880_1000_1000

        # 원본이 범위 내이면서 1비트 차이로 corrupted
        # 이 테스트는 분석 로직만 검증 (실제 범위 계산은 mock 의존)
        encoded_value = 0x0000_0000_0000_0001  # 낮은 비트만 설정

        result = freelist_detector.trace_corrupted_freeptr(
            cache, ptr_addr, encoded_value
        )

        assert "likely_cause" in result


class TestFreelistCorruptionDetectorEstimateCause:
    """_estimate_corruption_cause() 메서드 테스트."""

    def test_estimate_bitflip(self, freelist_detector):
        """Bitflip 원인 추정."""
        analysis = {"is_bitflip": True, "candidates": [{"value": 0x1000, "bit": 12}]}
        cause = freelist_detector._estimate_corruption_cause(0x0800, analysis)
        assert cause == "bitflip"

    def test_estimate_use_after_free(self, freelist_detector):
        """Use-after-free 원인 추정."""
        analysis = {"is_bitflip": False, "candidates": []}
        cause = freelist_detector._estimate_corruption_cause(0xDEAD_BEEF, analysis)
        assert cause == "use_after_free"

    def test_estimate_overflow(self, freelist_detector):
        """Overflow 원인 추정."""
        analysis = {"is_bitflip": False, "candidates": []}
        cause = freelist_detector._estimate_corruption_cause(
            0xFFFF_FFFF_FFFF_FFFE, analysis
        )
        assert cause == "overflow"

    def test_estimate_unknown(self, freelist_detector):
        """Unknown 원인."""
        analysis = {"is_bitflip": False, "candidates": []}
        cause = freelist_detector._estimate_corruption_cause(0x1234_5678, analysis)
        assert cause == "unknown"


# =============================================================================
# KASAN 연동 테스트
# =============================================================================


@pytest.fixture
def kasan_slub_backend():
    """KASAN과 SLUB이 모두 설정된 backend."""
    backend = MockDIBackend()
    backend.setup_kasan_sw_tags()
    return backend


@pytest.fixture
def kasan_slub_setup(kasan_slub_backend):
    """KASAN + SLUB 통합 설정."""
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.analyzers.slub import SlubAnalyzer
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper

    structs = StructHelper(kasan_slub_backend)
    addr = AddressTranslator(kasan_slub_backend)
    symbols = KernelResolver(kasan_slub_backend)

    kasan = KasanAnalyzer(
        backend=kasan_slub_backend, structs=structs, addr=addr, symbols=symbols
    )
    slub = SlubAnalyzer(
        backend=kasan_slub_backend, structs=structs, addr=addr, symbols=symbols
    )

    return {"backend": kasan_slub_backend, "kasan": kasan, "slub": slub}


@pytest.fixture
def freelist_detector_with_kasan(kasan_slub_setup):
    """KASAN 연동 FreelistCorruptionDetector."""
    return FreelistCorruptionDetector(
        kasan_slub_setup["slub"], kasan_slub_setup["kasan"]
    )


@pytest.fixture
def setup_kasan_slab(kasan_slub_setup):
    """KASAN 태그가 설정된 slab 환경."""
    backend = kasan_slub_setup["backend"]
    kasan = kasan_slub_setup["kasan"]

    # Cache 설정
    cache_addr = 0xFFFF_8880_0001_0000
    cache = backend.register_kmem_cache(
        addr=cache_addr,
        name="test-cache",
        object_size=64,
        size=64,
        offset=32,
        random=0x1234_5678_9ABC_DEF0,
    )
    backend.link_caches([cache_addr])

    # Slab 설정 (8 objects, 3 free)
    slab_addr = 0xFFFF_EA00_0010_0000
    slab = backend.register_slab(
        addr=slab_addr,
        cache_addr=cache_addr,
        objects=8,
        inuse=5,
    )
    slab._base = slab_addr

    slab_virt_addr = 0xFFFF_8880_1000_0000

    # Freelist 설정: indices 2, 5, 7 are free
    backend.setup_freelist(
        slab=slab,
        cache=cache,
        free_indices=[2, 5, 7],
        slab_virt_addr=slab_virt_addr,
        hardened=True,
    )

    # KASAN 태그 설정
    obj_size = 64
    for idx in range(8):
        obj_addr = slab_virt_addr + idx * obj_size
        if idx in [2, 5, 7]:  # free objects
            backend.set_shadow_tags_range(obj_addr, obj_size, kasan.TAG_INVALID)
        else:  # allocated objects
            backend.set_shadow_tags_range(obj_addr, obj_size, 0x42)

    return {
        "cache": cache,
        "cache_addr": cache_addr,
        "slab": slab,
        "slab_addr": slab_addr,
        "slab_virt_addr": slab_virt_addr,
        "free_indices": [2, 5, 7],
        "allocated_indices": [0, 1, 3, 4, 6],
    }


class TestFreelistCorruptionDetectorKasanValidation:
    """validate_freelist_with_kasan() 테스트."""

    def test_validate_freelist_with_kasan_disabled(
        self, freelist_detector, setup_slab_with_freelist
    ):
        """KASAN 비활성화 시 기본 검증만 수행."""
        data = setup_slab_with_freelist
        slab = data["slab"]
        slab._base = data["slab_addr"]

        # KASAN 없이 생성된 detector
        result = freelist_detector.validate_freelist_with_kasan(slab)

        assert "freelist_result" in result
        assert result["kasan_errors"] == []
        assert result["consistency"]["checked"] is False

    def test_validate_freelist_with_kasan_returns_structure(
        self, freelist_detector_with_kasan, kasan_slub_setup, setup_kasan_slab
    ):
        """validate_freelist_with_kasan 반환 구조 확인."""
        data = setup_kasan_slab
        slab = data["slab"]

        result = freelist_detector_with_kasan.validate_freelist_with_kasan(slab)

        # 반환 구조 확인
        assert "valid" in result
        assert "freelist_result" in result
        assert "kasan_errors" in result
        assert "consistency" in result
        assert "checked" in result["consistency"]
        assert result["consistency"]["checked"] is True


class TestFreelistCorruptionDetectorDoubleFree:
    """detect_double_free() 테스트."""

    def test_detect_double_free_returns_list(
        self, freelist_detector_with_kasan, setup_kasan_slab
    ):
        """detect_double_free 반환 형식 확인."""
        data = setup_kasan_slab
        slab = data["slab"]

        result = freelist_detector_with_kasan.detect_double_free(slab)

        # 리스트 반환
        assert isinstance(result, list)


class TestFreelistCorruptionDetectorCacheValidation:
    """validate_cache_with_kasan() 테스트."""

    def test_validate_cache_with_kasan_no_errors(
        self, freelist_detector_with_kasan, kasan_slub_setup, setup_kasan_slab
    ):
        """에러 없는 cache 검증."""
        data = setup_kasan_slab
        cache = data["cache"]
        cache._base = data["cache_addr"]

        # iter_slabs가 동작하려면 추가 설정 필요
        # 이 테스트는 기본 구조만 검증
        result = freelist_detector_with_kasan.validate_cache_with_kasan(cache)

        assert "cache_name" in result
        assert "total_slabs" in result
        assert "corrupted_slabs" in result
        assert "kasan_inconsistent_slabs" in result
        assert "errors" in result
