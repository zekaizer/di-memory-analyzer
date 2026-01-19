"""Bitflip 분석 모듈."""

from __future__ import annotations


class BitflipAnalyzer:
    """단일 비트 플립으로 인한 corruption 분석."""

    def analyze(self, corrupted: int, valid_range: tuple[int, int]) -> dict:
        """
        단일 bitflip으로 valid 값이 되는지 분석.

        64비트 값의 각 비트를 플립하여 유효 범위에 들어오는지 확인.

        Args:
            corrupted: corrupted 값
            valid_range: (start, end) 유효 범위 (start 포함, end 미포함)

        Returns:
            {
                "is_bitflip": bool,
                "candidates": list[dict],  # [{"value": int, "bit": int}, ...]
            }
        """
        candidates: list[dict] = []
        start, end = valid_range

        for bit in range(64):
            flipped = corrupted ^ (1 << bit)
            if start <= flipped < end:
                candidates.append({"value": flipped, "bit": bit})

        return {
            "is_bitflip": len(candidates) > 0,
            "candidates": candidates,
        }

    def find_flipped_bits(self, original: int, corrupted: int) -> list[int]:
        """
        두 값 사이에 플립된 비트 위치 찾기.

        Args:
            original: 원본 값
            corrupted: corrupted 값

        Returns:
            플립된 비트 위치 리스트 (0부터 시작)
        """
        diff = original ^ corrupted
        flipped_bits = []
        for bit in range(64):
            if diff & (1 << bit):
                flipped_bits.append(bit)
        return flipped_bits

    def is_single_bitflip(self, original: int, corrupted: int) -> bool:
        """
        단일 비트플립인지 확인.

        Args:
            original: 원본 값
            corrupted: corrupted 값

        Returns:
            단일 비트플립 여부
        """
        diff = original ^ corrupted
        # diff가 2의 거듭제곱이면 단일 비트 차이
        return diff != 0 and (diff & (diff - 1)) == 0

    def count_flipped_bits(self, original: int, corrupted: int) -> int:
        """
        플립된 비트 수 계산.

        Args:
            original: 원본 값
            corrupted: corrupted 값

        Returns:
            플립된 비트 수
        """
        diff = original ^ corrupted
        count = 0
        while diff:
            count += diff & 1
            diff >>= 1
        return count
