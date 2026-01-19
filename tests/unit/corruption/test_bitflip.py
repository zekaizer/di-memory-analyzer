"""BitflipAnalyzer 테스트."""

from __future__ import annotations

import pytest

from di_memory.corruption.bitflip import BitflipAnalyzer


@pytest.fixture
def bitflip_analyzer():
    """BitflipAnalyzer 인스턴스."""
    return BitflipAnalyzer()


class TestBitflipAnalyzerAnalyze:
    """analyze() 메서드 테스트."""

    def test_analyze_single_bitflip(self, bitflip_analyzer):
        """단일 비트플립으로 유효 범위 진입."""
        # valid range: 0x1000 ~ 0x2000
        valid_range = (0x1000, 0x2000)

        # 0x0800 ^ (1 << 12) = 0x1800 (valid!)
        corrupted = 0x0800
        result = bitflip_analyzer.analyze(corrupted, valid_range)

        assert result["is_bitflip"] is True
        assert any(c["bit"] == 12 for c in result["candidates"])

    def test_analyze_no_bitflip(self, bitflip_analyzer):
        """비트플립으로 유효 범위 진입 불가."""
        valid_range = (0x1000, 0x1100)
        corrupted = 0xDEAD_BEEF

        result = bitflip_analyzer.analyze(corrupted, valid_range)
        assert result["is_bitflip"] is False
        assert len(result["candidates"]) == 0

    def test_analyze_multiple_candidates(self, bitflip_analyzer):
        """여러 비트플립 후보."""
        # valid range: 0x1000 ~ 0x3000 (넓은 범위)
        valid_range = (0x1000, 0x3000)
        corrupted = 0x1000

        result = bitflip_analyzer.analyze(corrupted, valid_range)
        assert result["is_bitflip"] is True
        # bit 12, 13 등 여러 후보 가능
        assert len(result["candidates"]) >= 1


class TestBitflipAnalyzerFindFlippedBits:
    """find_flipped_bits() 메서드 테스트."""

    def test_find_single_flipped_bit(self, bitflip_analyzer):
        """단일 플립 비트 찾기."""
        original = 0x1000
        corrupted = 0x1100  # bit 8 flipped

        flipped = bitflip_analyzer.find_flipped_bits(original, corrupted)
        assert flipped == [8]

    def test_find_multiple_flipped_bits(self, bitflip_analyzer):
        """여러 플립 비트 찾기."""
        original = 0x0000
        corrupted = 0x0005  # bits 0, 2 flipped

        flipped = bitflip_analyzer.find_flipped_bits(original, corrupted)
        assert flipped == [0, 2]

    def test_find_no_flipped_bits(self, bitflip_analyzer):
        """플립된 비트 없음."""
        original = 0x1234
        corrupted = 0x1234

        flipped = bitflip_analyzer.find_flipped_bits(original, corrupted)
        assert flipped == []


class TestBitflipAnalyzerIsSingleBitflip:
    """is_single_bitflip() 메서드 테스트."""

    def test_is_single_bitflip_true(self, bitflip_analyzer):
        """단일 비트플립인 경우."""
        original = 0x1000
        corrupted = 0x1001  # bit 0 only

        assert bitflip_analyzer.is_single_bitflip(original, corrupted) is True

    def test_is_single_bitflip_false_multiple(self, bitflip_analyzer):
        """여러 비트 차이인 경우."""
        original = 0x1000
        corrupted = 0x1003  # bits 0, 1

        assert bitflip_analyzer.is_single_bitflip(original, corrupted) is False

    def test_is_single_bitflip_false_same(self, bitflip_analyzer):
        """동일 값인 경우."""
        original = 0x1234
        corrupted = 0x1234

        assert bitflip_analyzer.is_single_bitflip(original, corrupted) is False


class TestBitflipAnalyzerCountFlippedBits:
    """count_flipped_bits() 메서드 테스트."""

    def test_count_zero_flipped(self, bitflip_analyzer):
        """플립된 비트 없음."""
        assert bitflip_analyzer.count_flipped_bits(0x1234, 0x1234) == 0

    def test_count_one_flipped(self, bitflip_analyzer):
        """1개 비트 플립."""
        assert bitflip_analyzer.count_flipped_bits(0x1000, 0x1001) == 1

    def test_count_multiple_flipped(self, bitflip_analyzer):
        """여러 비트 플립."""
        assert bitflip_analyzer.count_flipped_bits(0x0000, 0x000F) == 4  # 4 bits

    def test_count_all_bits_different(self, bitflip_analyzer):
        """모든 비트 다름."""
        assert bitflip_analyzer.count_flipped_bits(0, 0xFF) == 8
