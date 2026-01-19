"""Stack depot 핸들에서 스택 트레이스 추출 (Linux 6.12+)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.backend import DIBackend
    from di_memory.core.kernel_resolver import KernelResolver


class StackDepotResolver:
    """
    Stack depot 핸들에서 스택 트레이스 추출 (Linux 6.12+).

    Linux 6.12+ lib/stackdepot.c 기반:

    Handle 구조 (union handle_parts, 32비트):
        - bits 0-20:  pool_index_plus_1 (21 bits)
        - bits 21-30: offset (10 bits)
        - bit 31:     extra (1 bit)

    struct stack_record {
        struct list_head hash_list;
        u32 hash;
        u32 size;                    // 스택 프레임 수
        union handle_parts handle;
        refcount_t count;
        unsigned long entries[];     // 스택 주소 배열
    };

    스택 주소 조회: stack_pools[pool_index][offset * DEPOT_STACK_ALIGN]
    """

    # Linux 6.12+ 상수 (lib/stackdepot.c)
    DEPOT_POOL_INDEX_BITS = 21
    DEPOT_OFFSET_BITS = 10
    DEPOT_EXTRA_BITS = 1
    DEPOT_STACK_ALIGN = 4  # sizeof(unsigned int)

    # Handle 비트 마스크
    POOL_INDEX_MASK = (1 << DEPOT_POOL_INDEX_BITS) - 1  # 0x1FFFFF
    OFFSET_MASK = (1 << DEPOT_OFFSET_BITS) - 1  # 0x3FF

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

    def _parse_handle(self, handle: int) -> tuple[int, int, int]:
        """
        핸들에서 pool_index, offset, extra 추출 (Linux 6.12+).

        Handle 비트 구조:
            [31]    extra (1 bit)
            [30:21] offset (10 bits)
            [20:0]  pool_index_plus_1 (21 bits)

        Args:
            handle: depot_stack_handle_t (32비트)

        Returns:
            (pool_index, offset_in_pool, extra)
        """
        pool_index_plus_1 = handle & self.POOL_INDEX_MASK
        offset_raw = (handle >> self.DEPOT_POOL_INDEX_BITS) & self.OFFSET_MASK
        extra = (handle >> 31) & 0x1

        # pool_index_plus_1이 0이면 invalid handle
        if pool_index_plus_1 == 0:
            return -1, 0, extra

        pool_index = pool_index_plus_1 - 1
        # offset은 DEPOT_STACK_ALIGN 단위로 저장됨
        offset = offset_raw << self.DEPOT_STACK_ALIGN

        return pool_index, offset, extra

    def _get_entries_offset(self) -> int:
        """
        struct stack_record의 entries 오프셋 (캐싱).

        Linux 6.12+ struct stack_record:
            list_head hash_list (16)
            u32 hash (4)
            u32 size (4)
            union handle_parts handle (4)
            refcount_t count (4)
            entries[] (가변)

        총 고정 크기: 32 bytes
        """
        if self._record_entries_offset is not None:
            return self._record_entries_offset

        try:
            self._record_entries_offset = self._backend.offsetof(
                "struct stack_record", "entries"
            )
        except (KeyError, ValueError):
            # Linux 6.12+ 기본 오프셋
            # hash_list(16) + hash(4) + size(4) + handle(4) + count(4) = 32
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

        pool_index, offset, _ = self._parse_handle(handle)
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
        except (KeyError, ValueError):
            # Linux 6.12+ 기본: hash_list(16) + hash(4) = 20
            size_offset = 20

        try:
            size = self._backend.read_u32(record_addr + size_offset)
        except Exception:
            return []

        # 최대 프레임 수 제한 (CONFIG_STACKDEPOT_MAX_FRAMES 기본값 64)
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

    @staticmethod
    def encode_handle(pool_index: int, offset: int, extra: int = 0) -> int:
        """
        테스트용: pool_index, offset, extra를 핸들로 인코딩.

        Args:
            pool_index: pool 인덱스 (0-based)
            offset: pool 내 오프셋 (바이트 단위, DEPOT_STACK_ALIGN 배수)
            extra: extra 비트 (0 또는 1)

        Returns:
            depot_stack_handle_t (32비트)
        """
        pool_index_plus_1 = pool_index + 1
        offset_raw = offset >> StackDepotResolver.DEPOT_STACK_ALIGN

        handle = pool_index_plus_1 & StackDepotResolver.POOL_INDEX_MASK
        handle |= (offset_raw & StackDepotResolver.OFFSET_MASK) << StackDepotResolver.DEPOT_POOL_INDEX_BITS
        handle |= (extra & 0x1) << 31

        return handle
