"""Stack depot 핸들에서 스택 트레이스 추출."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend
    from di_memory.core.kernel_resolver import KernelResolver


class StackDepotResolver:
    """
    Stack depot 핸들에서 스택 트레이스 추출.

    Linux 커널의 lib/stackdepot.c 구조:
    - depot_stack_handle_t는 32비트 핸들
    - 핸들 구조: pool_index | offset | extra
    - stack_pools[pool_index][offset] 에서 실제 스택 데이터 조회

    struct stack_record {
        struct list_head hash_list;
        u32 hash;
        u32 size;                    # 스택 프레임 수
        unsigned long entries[];     # 스택 주소 배열
    };
    """

    # Stack depot 상수 (Linux 5.x+)
    # lib/stackdepot.c에서 정의
    DEPOT_POOL_ORDER = 2  # 페이지 단위
    DEPOT_STACK_ALIGN = 4

    def __init__(
        self,
        backend: DIBackend,
        symbols: KernelResolver,
    ) -> None:
        self._backend = backend
        self._symbols = symbols
        self._pools_addr: int | None = None

    @property
    def stack_pools(self) -> int | None:
        """stack_pools 심볼 주소."""
        if self._pools_addr is None:
            self._pools_addr = self._symbols.to_addr("stack_pools")
        return self._pools_addr

    def _parse_handle(self, handle: int) -> tuple[int, int, int]:
        """
        핸들에서 pool_index, offset, extra 추출.

        Linux 5.x+ 핸들 구조 (32비트):
        - 상위 비트: pool_index
        - 하위 비트: offset + extra

        Args:
            handle: depot_stack_handle_t (32비트)

        Returns:
            (pool_index, offset_in_pool, extra)
        """
        # 커널 버전에 따라 비트 구조가 다를 수 있음
        # Linux 5.x: pool_index(상위), offset(하위)
        # 기본적으로 상위 16비트가 pool_index
        pool_index = (handle >> 16) & 0xFFFF
        offset = (handle & 0xFFFF) << self.DEPOT_STACK_ALIGN
        extra = 0  # 사용하지 않음
        return pool_index, offset, extra

    def resolve_handle(self, handle: int) -> list[int]:
        """
        Stack depot 핸들에서 스택 주소 목록 추출.

        Args:
            handle: depot_stack_handle_t (32비트)

        Returns:
            스택 주소 리스트 [caller, ..., callee]
        """
        if handle == 0:
            return []

        pools_addr = self.stack_pools
        if pools_addr is None:
            return []

        pool_index, offset, _ = self._parse_handle(handle)

        # stack_pools[pool_index] 읽기 (포인터 배열)
        pool_ptr_addr = pools_addr + pool_index * 8  # sizeof(void*)
        pool_ptr = self._backend.read_pointer(pool_ptr_addr)
        if pool_ptr == 0:
            return []

        # stack_record 주소 계산
        record_addr = pool_ptr + offset

        # stack_record.size 읽기
        try:
            size_offset = self._backend.offsetof("struct stack_record", "size")
            size = self._backend.read_u32(record_addr + size_offset)
        except (KeyError, ValueError):
            return []

        # 최대 32 프레임으로 제한
        size = min(size, 32)
        if size == 0:
            return []

        # entries 배열 읽기
        try:
            entries_offset = self._backend.offsetof("struct stack_record", "entries")
        except (KeyError, ValueError):
            # 기본 오프셋 사용 (hash_list(16) + hash(4) + size(4) = 24)
            entries_offset = 24

        entries_addr = record_addr + entries_offset

        addrs: list[int] = []
        for i in range(size):
            addr = self._backend.read_pointer(entries_addr + i * 8)
            if addr == 0:
                break
            addrs.append(addr)

        return addrs

    def resolve_stack(self, handle: int) -> list[str]:
        """
        핸들에서 심볼로 resolved된 스택 반환.

        Args:
            handle: depot_stack_handle_t

        Returns:
            ["function_name+0xoffset", ...]
        """
        addrs = self.resolve_handle(handle)
        return self._symbols.resolve_stack(addrs)
