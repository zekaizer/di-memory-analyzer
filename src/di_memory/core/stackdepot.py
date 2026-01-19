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

    Handle 구조 (union handle_parts, 32비트):
        비트 필드 크기는 PAGE_SHIFT에 의존:
        - pool_index_plus_1: DEPOT_POOL_INDEX_BITS
        - offset: DEPOT_OFFSET_BITS = DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN
        - extra: STACK_DEPOT_EXTRA_BITS = 5

        x86_64 (PAGE_SHIFT=12) 기준:
        - bits 0-16:  pool_index_plus_1 (17 bits)
        - bits 17-26: offset (10 bits)
        - bits 27-31: extra (5 bits)

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

    # Linux 6.12+ 고정 상수 (include/linux/stackdepot.h)
    DEPOT_POOL_ORDER = 2
    DEPOT_STACK_ALIGN = 4  # sizeof(unsigned int)
    STACK_DEPOT_EXTRA_BITS = 5
    DEPOT_HANDLE_BITS = 32

    # PAGE_SHIFT 기본값 (x86_64, 4KB pages)
    DEFAULT_PAGE_SHIFT = 12

    def __init__(
        self,
        backend: DIBackend,
        symbols: KernelResolver,
    ) -> None:
        self._backend = backend
        self._symbols = symbols
        self._pools_addr: int | None = None
        self._record_entries_offset: int | None = None
        self._bit_layout: dict[str, int] | None = None

    @property
    def stack_pools(self) -> int | None:
        """stack_pools 심볼 주소."""
        if self._pools_addr is None:
            self._pools_addr = self._symbols.to_addr("stack_pools")
        return self._pools_addr

    def _get_bit_layout(self) -> dict[str, int]:
        """
        union handle_parts 비트 레이아웃 계산 (캐싱).

        Linux 6.12+ 기준:
            DEPOT_OFFSET_BITS = DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN
            DEPOT_POOL_INDEX_BITS = 32 - DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS

        Returns:
            {
                "page_shift": int,
                "pool_index_bits": int,
                "offset_bits": int,
                "extra_bits": int,
                "pool_index_mask": int,
                "offset_mask": int,
                "extra_mask": int,
            }
        """
        if self._bit_layout is not None:
            return self._bit_layout

        # PAGE_SHIFT 획득 시도
        page_shift = self._get_page_shift()

        # 비트 필드 크기 계산 (Linux 6.12+ 공식)
        offset_bits = self.DEPOT_POOL_ORDER + page_shift - self.DEPOT_STACK_ALIGN
        pool_index_bits = (
            self.DEPOT_HANDLE_BITS - offset_bits - self.STACK_DEPOT_EXTRA_BITS
        )
        extra_bits = self.STACK_DEPOT_EXTRA_BITS

        self._bit_layout = {
            "page_shift": page_shift,
            "pool_index_bits": pool_index_bits,
            "offset_bits": offset_bits,
            "extra_bits": extra_bits,
            "pool_index_mask": (1 << pool_index_bits) - 1,
            "offset_mask": (1 << offset_bits) - 1,
            "extra_mask": (1 << extra_bits) - 1,
        }

        return self._bit_layout

    def _get_page_shift(self) -> int:
        """
        PAGE_SHIFT 값 획득.

        시도 순서:
        1. CONFIG_PAGE_SHIFT (일부 아키텍처)
        2. PAGE_SIZE 심볼에서 계산
        3. 기본값 (12, 4KB pages)
        """
        # CONFIG_PAGE_SHIFT 시도
        config_val = self._symbols.get_config("CONFIG_PAGE_SHIFT")
        if isinstance(config_val, int):
            return config_val

        # PAGE_SIZE에서 계산 시도 (PAGE_SIZE = 1 << PAGE_SHIFT)
        page_size_addr = self._symbols.to_addr("PAGE_SIZE")
        if page_size_addr is not None:
            try:
                page_size = self._backend.read_u64(page_size_addr)
                if page_size > 0:
                    return page_size.bit_length() - 1
            except Exception:
                pass

        return self.DEFAULT_PAGE_SHIFT

    def _parse_handle(self, handle: int) -> tuple[int, int, int]:
        """
        핸들에서 pool_index, offset, extra 추출 (Linux 6.12+).

        Handle 비트 구조 (PAGE_SHIFT=12, x86_64 기준):
            [31:27] extra (5 bits)
            [26:17] offset (10 bits)
            [16:0]  pool_index_plus_1 (17 bits)

        Args:
            handle: depot_stack_handle_t (32비트)

        Returns:
            (pool_index, offset_in_pool, extra)
        """
        layout = self._get_bit_layout()

        pool_index_plus_1 = handle & layout["pool_index_mask"]
        offset_raw = (handle >> layout["pool_index_bits"]) & layout["offset_mask"]
        extra = (
            handle >> (layout["pool_index_bits"] + layout["offset_bits"])
        ) & layout["extra_mask"]

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

    def encode_handle(self, pool_index: int, offset: int, extra: int = 0) -> int:
        """
        테스트용: pool_index, offset, extra를 핸들로 인코딩.

        Args:
            pool_index: pool 인덱스 (0-based)
            offset: pool 내 오프셋 (바이트 단위, DEPOT_STACK_ALIGN 배수)
            extra: extra 비트 (0-31, 5 bits in Linux 6.12+)

        Returns:
            depot_stack_handle_t (32비트)
        """
        layout = self._get_bit_layout()

        pool_index_plus_1 = pool_index + 1
        offset_raw = offset >> self.DEPOT_STACK_ALIGN

        handle = pool_index_plus_1 & layout["pool_index_mask"]
        handle |= (offset_raw & layout["offset_mask"]) << layout["pool_index_bits"]
        handle |= (extra & layout["extra_mask"]) << (
            layout["pool_index_bits"] + layout["offset_bits"]
        )

        return handle

    @staticmethod
    def encode_handle_static(
        pool_index: int,
        offset: int,
        extra: int = 0,
        page_shift: int = 12,
    ) -> int:
        """
        정적 헬퍼: pool_index, offset, extra를 핸들로 인코딩.

        테스트에서 인스턴스 없이 사용할 수 있는 정적 메서드.

        Args:
            pool_index: pool 인덱스 (0-based)
            offset: pool 내 오프셋 (바이트 단위, DEPOT_STACK_ALIGN 배수)
            extra: extra 비트 (0-31)
            page_shift: PAGE_SHIFT 값 (기본값 12)

        Returns:
            depot_stack_handle_t (32비트)
        """
        # 비트 필드 크기 계산
        offset_bits = (
            2 + page_shift - 4
        )  # DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN
        pool_index_bits = (
            32 - offset_bits - 5
        )  # 32 - offset_bits - STACK_DEPOT_EXTRA_BITS

        pool_index_plus_1 = pool_index + 1
        offset_raw = offset >> 4  # DEPOT_STACK_ALIGN = 4

        pool_index_mask = (1 << pool_index_bits) - 1
        offset_mask = (1 << offset_bits) - 1
        extra_mask = (1 << 5) - 1

        handle = pool_index_plus_1 & pool_index_mask
        handle |= (offset_raw & offset_mask) << pool_index_bits
        handle |= (extra & extra_mask) << (pool_index_bits + offset_bits)

        return handle
