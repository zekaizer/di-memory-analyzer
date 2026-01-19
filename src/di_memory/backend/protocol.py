"""DIBackend Protocol - DI 환경 인터페이스 추상화."""

from __future__ import annotations

import ctypes
from typing import Protocol, runtime_checkable


@runtime_checkable
class DIBackend(Protocol):
    """
    DI Notebook 환경과의 인터페이스를 정의하는 Protocol.

    Production에서는 DINotebookWrapper를 래핑하고,
    Testing에서는 Mock 구현을 사용한다.

    Note:
        addr 파라미터는 int(주소) 또는 str(심볼 이름) 모두 허용.
    """

    # =========================================================================
    # Structure 메타정보
    # =========================================================================

    def sizeof(self, type_name: str) -> int:
        """
        타입의 크기를 반환.

        Args:
            type_name: 타입 이름 (예: "struct kmem_cache", "int")

        Returns:
            타입 크기 (bytes)

        Raises:
            KeyError: 타입이 존재하지 않는 경우
        """
        ...

    def offsetof(self, struct_name: str, member: str) -> int:
        """
        구조체 멤버의 오프셋을 반환.

        Args:
            struct_name: 구조체 이름 (예: "struct kmem_cache")
            member: 멤버 이름 (예: "object_size")

        Returns:
            멤버 오프셋 (bytes)

        Raises:
            KeyError: 구조체 또는 멤버가 존재하지 않는 경우
        """
        ...

    def has_member(self, struct_name: str, member: str) -> bool:
        """
        구조체에 특정 멤버가 존재하는지 확인.

        Args:
            struct_name: 구조체 이름
            member: 멤버 이름

        Returns:
            멤버 존재 여부
        """
        ...

    # =========================================================================
    # Memory 읽기
    # =========================================================================

    def read_type(
        self, addr: int | str, type_name: str | None = None
    ) -> ctypes.Structure | int:
        """
        메모리에서 타입 데이터를 읽어 반환.

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)
            type_name: 타입 이름 (예: "struct kmem_cache", "int")
                       addr이 심볼(str)인 경우 생략 가능 (심볼에서 타입 추론)

        Returns:
            struct인 경우 ctypes.Structure, 기본 타입인 경우 int

        Note:
            struct 반환 시 ._base 속성에 원본 주소가 저장됨.
        """
        ...

    def read_u8(self, addr: int | str) -> int:
        """
        1바이트 unsigned 정수 읽기.

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)

        Returns:
            0-255 범위의 정수
        """
        ...

    def read_u16(self, addr: int | str) -> int:
        """
        2바이트 unsigned 정수 읽기 (little-endian).

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)

        Returns:
            0-65535 범위의 정수
        """
        ...

    def read_u32(self, addr: int | str) -> int:
        """
        4바이트 unsigned 정수 읽기 (little-endian).

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)

        Returns:
            0-4294967295 범위의 정수
        """
        ...

    def read_u64(self, addr: int | str) -> int:
        """
        8바이트 unsigned 정수 읽기 (little-endian).

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)

        Returns:
            64비트 unsigned 정수
        """
        ...

    def read_bytes(self, addr: int | str, size: int) -> bytes:
        """
        메모리에서 바이트 시퀀스 읽기.

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)
            size: 읽을 바이트 수

        Returns:
            읽은 바이트 데이터
        """
        ...

    def read_pointer(self, addr: int | str) -> int:
        """
        아키텍처에 따라 포인터 읽기 (32bit: 4바이트, 64bit: 8바이트).

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)

        Returns:
            포인터 값
        """
        ...

    def read_string(self, addr: int | str, max_len: int = 256) -> str:
        """
        null-terminated 문자열 읽기.

        Args:
            addr: 메모리 주소 (int) 또는 심볼 이름 (str)
            max_len: 최대 읽을 길이

        Returns:
            디코딩된 문자열
        """
        ...

    # =========================================================================
    # Symbol
    # =========================================================================

    def symbol_to_addr(self, name: str) -> int | None:
        """
        심볼 이름을 주소로 변환.

        Args:
            name: 심볼 이름 (예: "slab_caches")

        Returns:
            심볼 주소 또는 None (심볼이 없는 경우)
        """
        ...

    def addr_to_symbol(self, addr: int) -> tuple[str, int] | None:
        """
        주소를 가장 가까운 심볼과 오프셋으로 변환.

        Args:
            addr: 메모리 주소

        Returns:
            (심볼 이름, 오프셋) tuple 또는 None (심볼이 없는 경우)
            예: ("kmem_cache_alloc", 0x42)
        """
        ...

    def is_symbol_valid(self, name: str) -> bool:
        """
        심볼이 유효한지 확인.

        Args:
            name: 심볼 이름

        Returns:
            심볼 존재 여부
        """
        ...

    # =========================================================================
    # Kernel Config
    # =========================================================================

    def get_enum(self, enum_name: str) -> dict[str, int] | None:
        """
        Enum 전체를 dict로 반환.

        Args:
            enum_name: enum 타입 이름 (예: "pageflags", "zone_type")

        Returns:
            {member_name: value} dict 또는 None (enum이 없는 경우)
        """
        ...

    def get_enum_value(self, enum_name: str, member: str) -> int | None:
        """
        Enum 특정 멤버의 값 조회.

        Args:
            enum_name: enum 타입 이름
            member: 멤버 이름 (예: "PG_slab", "ZONE_NORMAL")

        Returns:
            멤버 값 또는 None (없는 경우)
        """
        ...

    def get_config(self, config_name: str) -> bool | int | str | None:
        """
        커널 config 값 조회.

        Args:
            config_name: config 이름 (예: "CONFIG_SLUB_DEBUG")

        Returns:
            config 값 또는 None (config가 없는 경우)
            - bool: y -> True, n -> False
            - int: 숫자 값
            - str: 문자열 값
        """
        ...

    # =========================================================================
    # 주소 변환
    # =========================================================================

    def virt_to_phys(self, vaddr: int) -> int | None:
        """
        가상 주소를 물리 주소로 변환.

        Args:
            vaddr: 가상 주소

        Returns:
            물리 주소 또는 None (변환 불가능한 경우)
        """
        ...

    def phys_to_virt(self, paddr: int) -> int:
        """
        물리 주소를 가상 주소로 변환.

        Args:
            paddr: 물리 주소

        Returns:
            가상 주소
        """
        ...

    # =========================================================================
    # Per-CPU
    # =========================================================================

    def per_cpu(self, symbol: str, cpu_id: int) -> int:
        """
        per-cpu 변수의 특정 CPU 인스턴스 주소 반환.

        Args:
            symbol: per-cpu 심볼 이름
            cpu_id: CPU 번호

        Returns:
            해당 CPU의 변수 주소
        """
        ...

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
        ...
