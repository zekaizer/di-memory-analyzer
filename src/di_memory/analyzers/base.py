"""Analyzer 기본 클래스."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend.protocol import DIBackend
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper


class BaseAnalyzer:
    """모든 Analyzer의 기본 클래스."""

    def __init__(
        self,
        backend: DIBackend,
        structs: StructHelper,
        addr: AddressTranslator,
        symbols: KernelResolver,
    ) -> None:
        """
        BaseAnalyzer 초기화.

        Args:
            backend: DIBackend 인스턴스
            structs: StructHelper 인스턴스
            addr: AddressTranslator 인스턴스
            symbols: KernelResolver 인스턴스
        """
        self._backend = backend
        self._structs = structs
        self._addr = addr
        self._symbols = symbols
