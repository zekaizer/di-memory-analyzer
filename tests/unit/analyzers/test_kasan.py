"""KasanAnalyzer 테스트 (SW_TAGS mode)."""

from __future__ import annotations

import pytest

from tests.conftest import MockDIBackend

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def setup_shadow_tags(kasan_mock_backend: MockDIBackend):
    """기본 shadow 태그 설정."""
    # 연속된 메모리 영역에 태그 설정
    base_addr = 0xFFFF_8881_0000_0000

    # Object 1: tag 0x42, 64 bytes (4 granules)
    kasan_mock_backend.set_shadow_tags_range(base_addr, 64, 0x42)

    # Redzone: tag 0xFE (invalid), 16 bytes
    kasan_mock_backend.set_shadow_tags_range(base_addr + 64, 16, 0xFE)

    # Object 2: tag 0x43, 64 bytes (4 granules)
    kasan_mock_backend.set_shadow_tags_range(base_addr + 80, 64, 0x43)

    # Freed object: tag 0xFE
    kasan_mock_backend.set_shadow_tags_range(base_addr + 144, 64, 0xFE)

    # Kernel (untagged): tag 0xFF
    kasan_mock_backend.set_shadow_tags_range(base_addr + 208, 64, 0xFF)

    return {
        "base": base_addr,
        "obj1_tag": 0x42,
        "obj2_tag": 0x43,
        "redzone_tag": 0xFE,
        "kernel_tag": 0xFF,
    }


# =============================================================================
# Properties 테스트
# =============================================================================


class TestKasanAnalyzerProperties:
    """Properties 테스트."""

    def test_is_enabled(self, kasan_analyzer):
        """CONFIG_KASAN 확인."""
        assert kasan_analyzer.is_enabled is True

    def test_is_sw_tags(self, kasan_analyzer):
        """CONFIG_KASAN_SW_TAGS 확인."""
        assert kasan_analyzer.is_sw_tags is True

    def test_shadow_offset(self, kasan_analyzer):
        """shadow_offset 조회."""
        assert kasan_analyzer.shadow_offset == 0xDFFF_FC00_0000_0000

    def test_constants(self, kasan_analyzer):
        """상수 값 확인."""
        assert kasan_analyzer.TAG_SHIFT == 56
        assert kasan_analyzer.GRANULE_SIZE == 16
        assert kasan_analyzer.SHADOW_SCALE_SHIFT == 4
        assert kasan_analyzer.TAG_INVALID == 0xFE
        assert kasan_analyzer.TAG_KERNEL == 0xFF


# =============================================================================
# Tag 조작 테스트
# =============================================================================


class TestKasanAnalyzerTagManipulation:
    """Pointer tag 조작 테스트."""

    def test_get_tag(self, kasan_analyzer):
        """포인터 태그 추출."""
        ptr = 0xA5_00_FFFF_8881_0000
        assert kasan_analyzer.get_tag(ptr) == 0xA5

    def test_get_tag_zero(self, kasan_analyzer):
        """태그 0 추출."""
        ptr = 0x00_FF_FFFF_8881_0000
        assert kasan_analyzer.get_tag(ptr) == 0x00

    def test_get_tag_kernel(self, kasan_analyzer):
        """커널 태그 (0xFF) 추출."""
        ptr = 0xFFFF_FFFF_8881_0000
        assert kasan_analyzer.get_tag(ptr) == 0xFF

    def test_set_tag(self, kasan_analyzer):
        """태그 설정."""
        addr = 0xFFFF_FFFF_8881_0000
        tagged = kasan_analyzer.set_tag(addr, 0x42)
        assert kasan_analyzer.get_tag(tagged) == 0x42
        # 하위 주소 부분 유지
        assert (tagged & 0x00FF_FFFF_FFFF_FFFF) == (addr & 0x00FF_FFFF_FFFF_FFFF)

    def test_set_tag_replace(self, kasan_analyzer):
        """기존 태그 교체."""
        ptr = 0xA5_00_FFFF_8881_0000
        new_ptr = kasan_analyzer.set_tag(ptr, 0x42)
        assert kasan_analyzer.get_tag(new_ptr) == 0x42

    def test_reset_tag(self, kasan_analyzer):
        """태그 제거 (커널 주소 복원)."""
        ptr = 0xA5_00_FFFF_8881_0000
        untagged = kasan_analyzer.reset_tag(ptr)
        # 상위 바이트가 0xFF로 설정됨
        assert (untagged >> 56) == 0xFF
        # 하위 주소는 유지
        assert (untagged & 0x00FF_FFFF_FFFF_FFFF) == (ptr & 0x00FF_FFFF_FFFF_FFFF)


# =============================================================================
# Shadow 변환 테스트
# =============================================================================


class TestKasanAnalyzerShadow:
    """Shadow memory 변환 테스트."""

    def test_mem_to_shadow(self, kasan_analyzer):
        """메모리 → shadow 변환."""
        addr = 0xFFFF_8881_0000_0000
        shadow = kasan_analyzer.mem_to_shadow(addr)
        # (addr >> 4) + shadow_offset
        expected = (addr >> 4) + 0xDFFF_FC00_0000_0000
        assert shadow == expected

    def test_mem_to_shadow_tagged(self, kasan_analyzer):
        """Tagged 포인터의 shadow 변환."""
        ptr = 0x42_00_FFFF_8881_0000
        shadow = kasan_analyzer.mem_to_shadow(ptr)
        # 태그 제거 (상위 바이트를 0xFF로) 후 변환
        untagged = ptr | (0xFF << 56)  # 0xFF_00_FFFF_8881_0000
        expected = (untagged >> 4) + 0xDFFF_FC00_0000_0000
        assert shadow == expected

    def test_shadow_to_mem(self, kasan_analyzer):
        """Shadow → 메모리 역변환."""
        shadow = (0xFFFF_8881_0000_0000 >> 4) + 0xDFFF_FC00_0000_0000
        addr = kasan_analyzer.shadow_to_mem(shadow)
        assert addr == 0xFFFF_8881_0000_0000

    def test_get_mem_tag(self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags):
        """메모리 태그 조회."""
        base = setup_shadow_tags["base"]
        # Object 1의 태그
        assert kasan_analyzer.get_mem_tag(base) == 0x42
        # Redzone 태그
        assert kasan_analyzer.get_mem_tag(base + 64) == 0xFE
        # Object 2의 태그
        assert kasan_analyzer.get_mem_tag(base + 80) == 0x43

    def test_get_mem_tags(self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags):
        """범위의 메모리 태그 조회."""
        base = setup_shadow_tags["base"]
        tags = kasan_analyzer.get_mem_tags(base, 64)
        assert len(tags) == 4  # 64 bytes = 4 granules
        assert all(t == 0x42 for t in tags)


# =============================================================================
# Tag 검증 테스트
# =============================================================================


class TestKasanAnalyzerTagValidation:
    """Tag 검증 테스트."""

    def test_tags_match_equal(self, kasan_analyzer):
        """동일 태그."""
        assert kasan_analyzer.tags_match(0x42, 0x42) is True

    def test_tags_match_different(self, kasan_analyzer):
        """다른 태그."""
        assert kasan_analyzer.tags_match(0x42, 0x43) is False

    def test_tags_match_kernel_ptr(self, kasan_analyzer):
        """Match-all 포인터 태그 (0xFF)."""
        assert kasan_analyzer.tags_match(0xFF, 0x42) is True

    def test_tags_match_kernel_mem(self, kasan_analyzer):
        """Match-all 메모리 태그 (0xFF)."""
        assert kasan_analyzer.tags_match(0x42, 0xFF) is True

    def test_tags_match_invalid(self, kasan_analyzer):
        """Invalid 태그 (0xFE)와 불일치."""
        assert kasan_analyzer.tags_match(0x42, 0xFE) is False

    def test_is_valid_tag(self, kasan_analyzer):
        """유효 태그 범위."""
        assert kasan_analyzer.is_valid_tag(0x00) is True
        assert kasan_analyzer.is_valid_tag(0x42) is True
        assert kasan_analyzer.is_valid_tag(0xFD) is True
        assert kasan_analyzer.is_valid_tag(0xFE) is False
        assert kasan_analyzer.is_valid_tag(0xFF) is False

    def test_is_match_all(self, kasan_analyzer):
        """Match-all 태그."""
        assert kasan_analyzer.is_match_all(0xFF) is True
        assert kasan_analyzer.is_match_all(0x42) is False
        assert kasan_analyzer.is_match_all(0xFE) is False


# =============================================================================
# 접근 검사 테스트
# =============================================================================


class TestKasanAnalyzerAccessCheck:
    """접근 검사 테스트."""

    def test_check_access_valid(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """유효한 접근."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x42)

        result = kasan_analyzer.check_access(ptr, 64)
        assert result["valid"] is True
        assert result["ptr_tag"] == 0x42
        assert len(result["granules"]) == 4
        assert all(g["match"] for g in result["granules"])
        assert result["first_mismatch"] is None

    def test_check_access_mismatch(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """태그 불일치."""
        base = setup_shadow_tags["base"]
        # 잘못된 태그로 접근
        ptr = kasan_analyzer.set_tag(base, 0x99)

        result = kasan_analyzer.check_access(ptr, 64)
        assert result["valid"] is False
        assert result["ptr_tag"] == 0x99
        assert result["first_mismatch"] is not None

    def test_check_access_oob(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """OOB 접근 (redzone 진입)."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x42)

        # Object 경계를 넘어서 접근 (64 + 16 = 80 bytes)
        result = kasan_analyzer.check_access(ptr, 80)
        assert result["valid"] is False
        # Redzone에서 불일치 발생
        assert result["first_mismatch"] == base + 64

    def test_check_access_kernel_tag(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Kernel 태그 (match-all) 접근."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0xFF)

        result = kasan_analyzer.check_access(ptr, 64)
        assert result["valid"] is True


# =============================================================================
# Granule 분석 테스트
# =============================================================================


class TestKasanAnalyzerGranule:
    """Granule 분석 테스트."""

    def test_round_down(self, kasan_analyzer):
        """Granule 내림."""
        assert kasan_analyzer.round_down(0x1000) == 0x1000
        assert kasan_analyzer.round_down(0x1005) == 0x1000
        assert kasan_analyzer.round_down(0x100F) == 0x1000
        assert kasan_analyzer.round_down(0x1010) == 0x1010

    def test_round_up(self, kasan_analyzer):
        """Granule 올림."""
        assert kasan_analyzer.round_up(0x1000) == 0x1000
        assert kasan_analyzer.round_up(0x1001) == 0x1010
        assert kasan_analyzer.round_up(0x100F) == 0x1010
        assert kasan_analyzer.round_up(0x1010) == 0x1010

    def test_iter_granules(self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags):
        """Granule 순회."""
        base = setup_shadow_tags["base"]
        granules = list(kasan_analyzer.iter_granules(base, 64))

        assert len(granules) == 4
        for addr, tag in granules:
            assert tag == 0x42
            assert addr % 16 == 0


# =============================================================================
# 메모리 상태 분석 테스트
# =============================================================================


class TestKasanAnalyzerMemoryState:
    """메모리 상태 분석 테스트."""

    def test_get_memory_state_accessible(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Accessible 상태."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x42)

        state = kasan_analyzer.get_memory_state(ptr)
        assert state["ptr_tag"] == 0x42
        assert state["mem_tag"] == 0x42
        assert state["match"] is True
        assert state["state"] == "accessible"

    def test_get_memory_state_freed(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Freed/invalid 상태."""
        base = setup_shadow_tags["base"]
        freed_addr = base + 144
        ptr = kasan_analyzer.set_tag(freed_addr, 0x42)

        state = kasan_analyzer.get_memory_state(ptr)
        assert state["mem_tag"] == 0xFE
        assert state["state"] == "freed/invalid"

    def test_get_memory_state_mismatch(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """Tag mismatch 상태."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x99)  # 잘못된 태그

        state = kasan_analyzer.get_memory_state(ptr)
        assert state["ptr_tag"] == 0x99
        assert state["mem_tag"] == 0x42
        assert state["match"] is False
        assert state["state"] == "tag mismatch"

    def test_analyze_region(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """영역 분석."""
        base = setup_shadow_tags["base"]

        # Object 1 + redzone + Object 2 영역 분석
        result = kasan_analyzer.analyze_region(base, 144)

        assert result["granule_count"] == 9  # 144 / 16
        assert 0x42 in result["unique_tags"]
        assert 0x43 in result["unique_tags"]
        assert 0xFE in result["unique_tags"]
        # transitions: 0x42->0xFE, 0xFE->0x43
        assert len(result["transitions"]) == 2


# =============================================================================
# Corruption 탐지 테스트
# =============================================================================


class TestKasanAnalyzerCorruption:
    """Corruption 탐지 테스트."""

    def test_detect_tag_mismatch_none(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """불일치 없음."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x42)

        result = kasan_analyzer.detect_tag_mismatch(ptr, 64)
        assert result is None

    def test_detect_tag_mismatch_found(
        self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags
    ):
        """불일치 탐지."""
        base = setup_shadow_tags["base"]
        ptr = kasan_analyzer.set_tag(base, 0x99)

        result = kasan_analyzer.detect_tag_mismatch(ptr, 64)
        assert result is not None
        assert result["ptr_tag"] == 0x99
        assert len(result["mismatches"]) == 4

    def test_classify_bug_type_uaf(self, kasan_analyzer):
        """UAF 버그 분류."""
        bug = kasan_analyzer.classify_bug_type(0x42, 0xFE)
        assert bug == "use-after-free"

    def test_classify_bug_type_oob(self, kasan_analyzer):
        """OOB 버그 분류."""
        bug = kasan_analyzer.classify_bug_type(0x42, 0xFF)
        assert bug == "out-of-bounds"

    def test_classify_bug_type_mismatch(self, kasan_analyzer):
        """Tag mismatch 버그 분류."""
        bug = kasan_analyzer.classify_bug_type(0x42, 0x43)
        assert bug == "tag-mismatch"


# =============================================================================
# 출력/포맷팅 테스트
# =============================================================================


class TestKasanAnalyzerFormatting:
    """출력/포맷팅 테스트."""

    def test_format_ptr(self, kasan_analyzer):
        """Tagged pointer 포맷."""
        ptr = 0x42_00_FFFF_8881_0000
        formatted = kasan_analyzer.format_ptr(ptr)
        assert "[42]" in formatted
        assert "ffff" in formatted.lower()

    def test_format_ptr_kernel(self, kasan_analyzer):
        """Kernel pointer 포맷."""
        ptr = 0xFFFF_FFFF_8881_0000
        formatted = kasan_analyzer.format_ptr(ptr)
        assert "[ff]" in formatted

    def test_dump_tags(self, kasan_analyzer, kasan_mock_backend, setup_shadow_tags):
        """태그 덤프."""
        base = setup_shadow_tags["base"]
        dump = kasan_analyzer.dump_tags(base, 64)

        # 4개의 granule이 출력됨
        assert "[42]" in dump
        assert "0x" in dump.lower()
