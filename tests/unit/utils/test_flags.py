"""PageFlagsHelper 테스트."""

from di_memory.utils.flags import (
    PG_BUDDY,
    PG_HEAD,
    PG_LOCKED,
    PG_RESERVED,
    PG_SLAB,
    PageFlagsHelper,
)


class TestPageFlagsHelper:
    """PageFlagsHelper 테스트."""

    def test_get_bit(self, page_flags_helper: PageFlagsHelper) -> None:
        """플래그 비트 위치 조회."""
        assert page_flags_helper.get_bit(PG_LOCKED) == 0
        assert page_flags_helper.get_bit(PG_SLAB) == 10
        assert page_flags_helper.get_bit(PG_HEAD) == 6

    def test_get_bit_unknown(self, page_flags_helper: PageFlagsHelper) -> None:
        """존재하지 않는 플래그."""
        assert page_flags_helper.get_bit("PG_unknown") is None

    def test_test_flag(self, page_flags_helper: PageFlagsHelper) -> None:
        """플래그 설정 여부 확인."""
        flags = (1 << 0) | (1 << 10)  # PG_locked | PG_slab

        assert page_flags_helper.test_flag(flags, PG_LOCKED) is True
        assert page_flags_helper.test_flag(flags, PG_SLAB) is True
        assert page_flags_helper.test_flag(flags, PG_HEAD) is False

    def test_test_flag_unknown(self, page_flags_helper: PageFlagsHelper) -> None:
        """존재하지 않는 플래그 테스트."""
        assert page_flags_helper.test_flag(0xFFFF, "PG_unknown") is False

    def test_decode(self, page_flags_helper: PageFlagsHelper) -> None:
        """플래그 디코딩."""
        flags = (1 << 0) | (1 << 6) | (1 << 10)  # locked | head | slab

        result = page_flags_helper.decode(flags)

        assert PG_LOCKED in result
        assert PG_HEAD in result
        assert PG_SLAB in result
        assert len(result) == 3

    def test_decode_empty(self, page_flags_helper: PageFlagsHelper) -> None:
        """빈 플래그 디코딩."""
        result = page_flags_helper.decode(0)
        assert result == []

    def test_decode_multiple(self, page_flags_helper: PageFlagsHelper) -> None:
        """여러 플래그 디코딩."""
        flags = (1 << 25) | (1 << 26)  # reserved | buddy

        result = page_flags_helper.decode(flags)

        assert PG_RESERVED in result
        assert PG_BUDDY in result
