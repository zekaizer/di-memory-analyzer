"""구조체 메타정보 및 읽기 헬퍼."""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend


class StructHelper:
    """DIBackend의 구조체 관련 기능을 편리하게 래핑."""

    def __init__(self, backend: DIBackend) -> None:
        self._backend = backend

    # =========================================================================
    # 메타정보
    # =========================================================================

    def sizeof(self, type_name: str) -> int:
        """타입의 크기를 반환."""
        return self._backend.sizeof(type_name)

    def offsetof(self, struct_name: str, member: str) -> int:
        """구조체 멤버의 오프셋을 반환."""
        return self._backend.offsetof(struct_name, member)

    def has_member(self, struct_name: str, member: str) -> bool:
        """구조체에 특정 멤버가 존재하는지 확인."""
        return self._backend.has_member(struct_name, member)

    # =========================================================================
    # 읽기
    # =========================================================================

    def read(
        self, addr: int | str, type_name: str | None = None
    ) -> ctypes.Structure | int:
        """
        메모리에서 타입 데이터를 읽어 반환.

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)
            type_name: 타입 이름. addr이 심볼인 경우 생략 가능.

        Returns:
            struct인 경우 ctypes.Structure (._base 속성 포함), 기본 타입인 경우 int
        """
        result = self._backend.read_type(addr, type_name)
        # struct인 경우 ._base 속성에 원본 주소 저장
        if isinstance(result, ctypes.Structure) and isinstance(addr, int):
            result._base = addr
        return result

    def read_member(
        self,
        addr: int,
        struct_name: str,
        member: str,
        member_type: str | None = None,
    ) -> ctypes.Structure | int:
        """
        구조체의 특정 멤버를 읽어 반환.

        Args:
            addr: 구조체 시작 주소
            struct_name: 구조체 이름
            member: 멤버 이름
            member_type: 멤버 타입 이름 (생략 시 포인터로 읽음)

        Returns:
            멤버 값
        """
        offset = self._backend.offsetof(struct_name, member)
        member_addr = addr + offset
        if member_type is not None:
            return self._backend.read_type(member_addr, member_type)
        return self._backend.read_pointer(member_addr)

    # =========================================================================
    # Container
    # =========================================================================

    def container_of(self, addr: int, struct_name: str, member: str) -> int:
        """
        멤버 주소에서 구조체 시작 주소 계산.

        Args:
            addr: 멤버의 주소
            struct_name: 구조체 이름
            member: 멤버 이름

        Returns:
            구조체 시작 주소
        """
        return self._backend.container_of(addr, struct_name, member)

    # =========================================================================
    # 리스트 순회
    # =========================================================================

    def list_for_each_entry(
        self, head: int, struct_name: str, member: str
    ) -> Iterator[ctypes.Structure]:
        """
        list_head를 순회하며 구조체를 반환.

        Args:
            head: list_head 주소 (순회 시작점)
            struct_name: 구조체 이름
            member: list_head 멤버 이름

        Yields:
            각 엔트리의 ctypes.Structure
        """
        # list_head.next 오프셋 (보통 0)
        next_offset = self._backend.offsetof("struct list_head", "next")
        member_offset = self._backend.offsetof(struct_name, member)

        # 첫 번째 엔트리
        current = self._backend.read_pointer(head + next_offset)

        while current != head:
            # container_of: list_head 주소에서 구조체 시작 주소 계산
            entry_addr = current - member_offset
            entry = self._backend.read_type(entry_addr, struct_name)
            entry._base = entry_addr
            yield entry

            # 다음 엔트리
            current = self._backend.read_pointer(current + next_offset)
