"""심볼 조회 및 커널 Config 관련 기능."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend


class KernelResolver:
    """심볼 조회 및 커널 Config 기능 제공."""

    def __init__(self, backend: DIBackend) -> None:
        self._backend = backend

    # =========================================================================
    # Symbol
    # =========================================================================

    def to_addr(self, name: str) -> int | None:
        """심볼 이름을 주소로 변환."""
        return self._backend.symbol_to_addr(name)

    def to_symbol(self, addr: int) -> tuple[str, int] | None:
        """주소를 가장 가까운 심볼과 오프셋으로 변환."""
        return self._backend.addr_to_symbol(addr)

    def is_symbol_valid(self, name: str) -> bool:
        """심볼이 유효한지 확인."""
        return self._backend.is_symbol_valid(name)

    def format_addr(self, addr: int) -> str:
        """
        주소를 심볼+오프셋 형태의 문자열로 포맷팅.

        Args:
            addr: 메모리 주소

        Returns:
            "symbol+0x42" 형태의 문자열, 심볼이 없으면 "0xaddr"
        """
        result = self._backend.addr_to_symbol(addr)
        if result is None:
            return f"0x{addr:x}"
        symbol, offset = result
        if offset == 0:
            return symbol
        return f"{symbol}+0x{offset:x}"

    def resolve_stack(self, addrs: list[int]) -> list[str]:
        """
        스택 트레이스 주소 목록을 심볼 문자열로 변환.

        Args:
            addrs: 스택 주소 목록

        Returns:
            포맷팅된 심볼 문자열 목록
        """
        return [self.format_addr(addr) for addr in addrs]

    # =========================================================================
    # Config
    # =========================================================================

    def get_config(self, config_name: str) -> bool | int | str | None:
        """
        커널 config 값 조회.

        Args:
            config_name: config 이름 (예: "CONFIG_SLUB_DEBUG")

        Returns:
            config 값 또는 None (config가 없는 경우)
        """
        return self._backend.get_config(config_name)

    def is_config_enabled(self, config_name: str) -> bool:
        """
        커널 config가 활성화되어 있는지 확인.

        Args:
            config_name: config 이름

        Returns:
            활성화 여부 (y, m, 또는 숫자 값이면 True)
        """
        value = self._backend.get_config(config_name)
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.lower() in ("y", "m")
        return False
