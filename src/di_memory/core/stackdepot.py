"""Stack depot 핸들에서 스택 트레이스 추출 (Linux 6.12+)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend
    from di_memory.core.kernel_resolver import KernelResolver


class StackDepotResolver:
    """
    Stack depot 핸들에서 스택 트레이스 추출 (Linux 6.12+).

    Linux 6.12+ include/linux/stackdepot.h 기반:

    union handle_parts {
        depot_stack_handle_t handle;
        struct {
            u32 pool_index_plus_1 : DEPOT_POOL_INDEX_BITS;
            u32 offset            : DEPOT_OFFSET_BITS;
            u32 extra             : STACK_DEPOT_EXTRA_BITS;
        };
    };

    비트필드에 직접 접근하여 파싱.
    """

    # Linux 6.12+ 고정 상수
    DEPOT_STACK_ALIGN = 4  # sizeof(unsigned int)

    def __init__(
        self,
        backend: DIBackend,
        symbols: KernelResolver,
    ) -> None:
        self._backend = backend
        self._symbols = symbols
        self._pools_addr: int | None = None
        self._record_entries_offset: int | None = None

    @property
    def stack_pools(self) -> int | None:
        """stack_pools 심볼 주소."""
        if self._pools_addr is None:
            self._pools_addr = self._symbols.to_addr("stack_pools")
        return self._pools_addr

    def _parse_handle_from_record(self, record_addr: int) -> tuple[int, int, int]:
        """
        stack_record.handle을 union handle_parts로 읽어서 파싱.

        비트필드 직접 접근:
        - pool_index_plus_1
        - offset
        - extra

        Args:
            record_addr: struct stack_record 주소

        Returns:
            (pool_index, offset_in_pool, extra)
        """
        try:
            # stack_record.handle 오프셋
            handle_offset = self._backend.offsetof("struct stack_record", "handle")
            handle_addr = record_addr + handle_offset

            # union handle_parts로 읽기 (비트필드 직접 접근)
            parts = self._backend.read_type(handle_addr, "union handle_parts")

            pool_index_plus_1 = parts.pool_index_plus_1
            offset_raw = parts.offset
            extra = parts.extra

            if pool_index_plus_1 == 0:
                return -1, 0, extra

            pool_index = pool_index_plus_1 - 1
            offset = offset_raw << self.DEPOT_STACK_ALIGN

            return pool_index, offset, extra

        except (KeyError, AttributeError):
            # union handle_parts 없으면 u32로 읽어서 수동 파싱
            handle = self._backend.read_u32(record_addr + handle_offset)
            return self._parse_handle_manual(handle)

    def _parse_handle_manual(self, handle: int) -> tuple[int, int, int]:
        """
        핸들 값을 수동 파싱 (fallback).

        Linux 6.12+ x86_64 (PAGE_SHIFT=12) 기준:
        - bits 0-16:  pool_index_plus_1 (17 bits)
        - bits 17-26: offset (10 bits)
        - bits 27-31: extra (5 bits)
        """
        if handle == 0:
            return -1, 0, 0

        # 기본값: PAGE_SHIFT=12
        pool_index_bits = 17
        offset_bits = 10

        pool_index_mask = (1 << pool_index_bits) - 1
        offset_mask = (1 << offset_bits) - 1
        extra_mask = 0x1F  # 5 bits

        pool_index_plus_1 = handle & pool_index_mask
        offset_raw = (handle >> pool_index_bits) & offset_mask
        extra = (handle >> (pool_index_bits + offset_bits)) & extra_mask

        if pool_index_plus_1 == 0:
            return -1, 0, extra

        pool_index = pool_index_plus_1 - 1
        offset = offset_raw << self.DEPOT_STACK_ALIGN

        return pool_index, offset, extra

    def _get_entries_offset(self) -> int:
        """struct stack_record의 entries 오프셋 (캐싱)."""
        if self._record_entries_offset is not None:
            return self._record_entries_offset

        try:
            self._record_entries_offset = self._backend.offsetof(
                "struct stack_record", "entries"
            )
        except (KeyError, ValueError):
            # Linux 6.12+ 기본 오프셋: 32
            self._record_entries_offset = 32

        return self._record_entries_offset

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

        # 먼저 수동 파싱으로 pool 위치 찾기
        pool_index, offset, _ = self._parse_handle_manual(handle)
        if pool_index < 0:
            return []

        # stack_pools[pool_index] 읽기
        try:
            pool_ptr = self._backend.read_pointer(pools_addr + pool_index * 8)
        except Exception:
            return []

        if pool_ptr == 0:
            return []

        # stack_record 주소 계산
        record_addr = pool_ptr + offset

        # stack_record.size 읽기
        try:
            size_offset = self._backend.offsetof("struct stack_record", "size")
            size = self._backend.read_u32(record_addr + size_offset)
        except Exception:
            return []

        # 최대 프레임 수 제한
        size = min(size, 64)
        if size == 0:
            return []

        # entries 배열 읽기
        entries_offset = self._get_entries_offset()
        entries_addr = record_addr + entries_offset

        addrs: list[int] = []
        for i in range(size):
            try:
                addr = self._backend.read_pointer(entries_addr + i * 8)
            except Exception:
                break
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

    def encode_handle(self, pool_index: int, offset: int, extra: int = 0) -> int:
        """
        테스트용: pool_index, offset, extra를 핸들로 인코딩.

        Linux 6.12+ x86_64 (PAGE_SHIFT=12) 기준.
        """
        pool_index_bits = 17
        offset_bits = 10

        pool_index_plus_1 = pool_index + 1
        offset_raw = offset >> self.DEPOT_STACK_ALIGN

        pool_index_mask = (1 << pool_index_bits) - 1
        offset_mask = (1 << offset_bits) - 1
        extra_mask = 0x1F

        handle = pool_index_plus_1 & pool_index_mask
        handle |= (offset_raw & offset_mask) << pool_index_bits
        handle |= (extra & extra_mask) << (pool_index_bits + offset_bits)

        return handle

    @staticmethod
    def encode_handle_static(
        pool_index: int,
        offset: int,
        extra: int = 0,
    ) -> int:
        """
        정적 헬퍼: 테스트 fixture에서 사용.

        Linux 6.12+ x86_64 (PAGE_SHIFT=12) 기준.
        """
        pool_index_bits = 17
        offset_bits = 10

        pool_index_plus_1 = pool_index + 1
        offset_raw = offset >> 4  # DEPOT_STACK_ALIGN

        pool_index_mask = (1 << pool_index_bits) - 1
        offset_mask = (1 << offset_bits) - 1
        extra_mask = 0x1F

        handle = pool_index_plus_1 & pool_index_mask
        handle |= (offset_raw & offset_mask) << pool_index_bits
        handle |= (extra & extra_mask) << (pool_index_bits + offset_bits)

        return handle
