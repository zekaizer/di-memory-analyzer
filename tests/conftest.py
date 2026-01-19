"""pytest fixtures."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


# =============================================================================
# Mock Structures
# =============================================================================


class MockAtomicT(ctypes.Structure):
    """Mock atomic_t 구조체."""

    _fields_ = [("counter", ctypes.c_int)]


class MockPage(ctypes.Structure):
    """Mock struct page."""

    _fields_ = [
        ("flags", ctypes.c_ulong),
        ("compound_head", ctypes.c_ulong),
        ("compound_order", ctypes.c_ubyte),
        ("_refcount", MockAtomicT),
        ("_mapcount", MockAtomicT),
    ]


class MockListHead(ctypes.Structure):
    """Mock struct list_head."""

    _fields_ = [
        ("next", ctypes.c_ulong),
        ("prev", ctypes.c_ulong),
    ]


class MockKmemCache(ctypes.Structure):
    """Mock struct kmem_cache (Linux 6.12+)."""

    _fields_ = [
        ("name", ctypes.c_ulong),  # char* - cache name pointer
        ("size", ctypes.c_uint),  # object size with padding
        ("object_size", ctypes.c_uint),  # actual object size
        ("offset", ctypes.c_uint),  # freelist pointer offset
        ("inuse", ctypes.c_uint),  # size actually used by object (for tracking offset)
        ("oo", ctypes.c_uint),  # objects per slab (packed)
        ("flags", ctypes.c_ulong),  # slab flags
        ("random", ctypes.c_ulong),  # FREELIST_HARDENED random value
        ("list", MockListHead),  # slab_caches list node
        ("cpu_slab", ctypes.c_ulong),  # per-cpu slab pointer
        ("node", ctypes.c_ulong),  # per-node pointer array
    ]


class MockSlab(ctypes.Structure):
    """Mock struct slab (Linux 6.1+)."""

    _fields_ = [
        ("__page_flags", ctypes.c_ulong),
        ("slab_cache", ctypes.c_ulong),  # kmem_cache pointer
        ("freelist", ctypes.c_ulong),  # free object list
        ("inuse", ctypes.c_uint),  # objects in use (or counters)
        ("objects", ctypes.c_uint),  # total objects
        ("frozen", ctypes.c_uint),  # slab frozen flag
        ("slab_list", MockListHead),  # partial/full list node
    ]


class MockKmemCacheCpu(ctypes.Structure):
    """Mock struct kmem_cache_cpu."""

    _fields_ = [
        ("freelist", ctypes.c_ulong),  # fast path free list
        ("tid", ctypes.c_ulong),  # transaction ID
        ("slab", ctypes.c_ulong),  # current slab
        ("partial", ctypes.c_ulong),  # partial slab list
    ]


class MockKmemCacheNode(ctypes.Structure):
    """Mock struct kmem_cache_node."""

    _fields_ = [
        ("partial", MockListHead),  # partial slab list
        ("nr_partial", ctypes.c_ulong),  # partial slab count
        ("full", MockListHead),  # full slab list (CONFIG_SLUB_DEBUG)
    ]


class MockTrack(ctypes.Structure):
    """Mock struct track (CONFIG_SLUB_DEBUG tracking)."""

    _fields_ = [
        ("addr", ctypes.c_ulong),  # Called from address
        ("handle", ctypes.c_uint),  # Stack depot handle (CONFIG_STACKDEPOT)
        ("cpu", ctypes.c_int),  # CPU that performed operation
        ("pid", ctypes.c_int),  # PID of process
        ("when", ctypes.c_ulong),  # jiffies timestamp
    ]


class MockStackRecord(ctypes.Structure):
    """Mock struct stack_record (stack depot)."""

    _fields_ = [
        ("hash_list_next", ctypes.c_ulong),  # list_head.next
        ("hash_list_prev", ctypes.c_ulong),  # list_head.prev
        ("hash", ctypes.c_uint),  # stack hash
        ("size", ctypes.c_uint),  # number of frames
        # entries[] is variable-length, handled separately
    ]


# =============================================================================
# Mock Backend
# =============================================================================


class MockDIBackend:
    """DIBackend Mock 구현."""

    def __init__(self) -> None:
        self._structs: dict[str, tuple[int, dict[str, int]]] = {}
        self._symbols: dict[str, int] = {}
        self._enums: dict[str, dict[str, int]] = {}
        self._configs: dict[str, bool | int | str] = {}
        self._memory: dict[int, bytes] = {}
        self._pages: dict[int, MockPage] = {}
        # SLUB 캐시
        self._caches: dict[int, MockKmemCache] = {}
        self._slabs: dict[int, MockSlab] = {}
        self._cache_cpus: dict[int, MockKmemCacheCpu] = {}
        self._cache_nodes: dict[int, MockKmemCacheNode] = {}
        self._strings: dict[int, str] = {}  # 문자열 저장
        # Tracking
        self._tracks: dict[int, MockTrack] = {}
        self._stack_depot: dict[int, list[int]] = {}  # handle -> [addrs]

        # 기본 설정
        self._setup_defaults()

    def _setup_defaults(self) -> None:
        """기본값 설정."""
        # PAGE_SHIFT 설정
        self._configs["CONFIG_PAGE_SHIFT"] = 12

        # pageflags enum 설정
        self._enums["pageflags"] = {
            "PG_locked": 0,
            "PG_writeback": 1,
            "PG_referenced": 2,
            "PG_uptodate": 3,
            "PG_dirty": 4,
            "PG_lru": 5,
            "PG_head": 6,
            "PG_waiters": 7,
            "PG_active": 8,
            "PG_workingset": 9,
            "PG_slab": 10,
            "PG_private": 11,
            "PG_reclaim": 12,
            "PG_swapbacked": 13,
            "PG_unevictable": 14,
            "PG_mlocked": 15,
            "PG_hwpoison": 20,
            "PG_reserved": 25,
            "PG_buddy": 26,
        }

        # slabflags enum 설정 (SLAB 플래그)
        self._enums["slabflags"] = {
            "SLAB_CONSISTENCY_CHECKS": 0x00000100,
            "SLAB_RED_ZONE": 0x00000400,
            "SLAB_POISON": 0x00000800,
            "SLAB_STORE_USER": 0x00010000,
            "SLAB_TRACE": 0x00200000,
        }

        # struct page 등록
        self._structs["struct page"] = (
            ctypes.sizeof(MockPage),
            {
                "flags": 0,
                "compound_head": 8,
                "compound_order": 16,
                "_refcount": 20,
                "_mapcount": 24,
            },
        )

        # struct list_head 등록
        self._structs["struct list_head"] = (
            ctypes.sizeof(MockListHead),
            {"next": 0, "prev": 8},
        )

        # struct kmem_cache 등록 (Linux 6.12+)
        # 필드 오프셋은 _fields_ 순서에 따라 계산
        self._structs["struct kmem_cache"] = (
            ctypes.sizeof(MockKmemCache),
            {
                "name": 0,
                "size": 8,
                "object_size": 12,
                "offset": 16,
                "inuse": 20,  # for tracking offset calculation
                "oo": 24,
                "flags": 32,  # 8-byte aligned
                "random": 40,
                "list": 48,  # MockListHead는 16바이트
                "cpu_slab": 64,
                "node": 72,
            },
        )

        # struct slab 등록 (Linux 6.1+)
        self._structs["struct slab"] = (
            ctypes.sizeof(MockSlab),
            {
                "__page_flags": 0,
                "slab_cache": 8,
                "freelist": 16,
                "inuse": 24,
                "objects": 28,
                "frozen": 32,
                "slab_list": 40,  # MockListHead
            },
        )

        # struct kmem_cache_cpu 등록
        self._structs["struct kmem_cache_cpu"] = (
            ctypes.sizeof(MockKmemCacheCpu),
            {
                "freelist": 0,
                "tid": 8,
                "slab": 16,
                "partial": 24,
            },
        )

        # struct kmem_cache_node 등록
        self._structs["struct kmem_cache_node"] = (
            ctypes.sizeof(MockKmemCacheNode),
            {
                "partial": 0,  # MockListHead
                "nr_partial": 16,
                "full": 24,  # MockListHead
            },
        )

        # struct track 등록 (CONFIG_SLUB_DEBUG)
        self._structs["struct track"] = (
            ctypes.sizeof(MockTrack),
            {
                "addr": 0,
                "handle": 8,  # CONFIG_STACKDEPOT
                "cpu": 12,
                "pid": 16,
                "when": 24,
            },
        )

        # struct stack_record 등록 (stack depot, Linux 6.12+)
        # Layout: hash_list(16) + hash(4) + size(4) + handle(4) + count(4) + entries[]
        self._structs["struct stack_record"] = (
            ctypes.sizeof(MockStackRecord),
            {
                "hash_list": 0,  # struct list_head (16 bytes)
                "hash": 16,
                "size": 20,
                "handle": 24,  # union handle_parts (4 bytes)
                "count": 28,  # refcount_t (4 bytes)
                "entries": 32,  # variable-length array starts here
            },
        )

        # SLUB 관련 CONFIG
        self._configs["CONFIG_SLUB_DEBUG"] = True
        self._configs["CONFIG_SLAB_FREELIST_HARDENED"] = True
        self._configs["CONFIG_STACKDEPOT"] = True

        # 기본 심볼
        self._symbols["vmemmap"] = 0xFFFF_EA00_0000_0000
        self._symbols["max_pfn"] = 0xFFFF_FFFF_8100_0000
        self._symbols["slab_caches"] = 0xFFFF_FFFF_8200_0000  # slab_caches list_head

        # vmemmap 포인터 값 설정
        self._memory[0xFFFF_EA00_0000_0000] = (0xFFFF_EA00_0000_0000).to_bytes(
            8, "little"
        )
        # max_pfn 값 설정 (예: 0x100000 = 1M pages)
        self._memory[0xFFFF_FFFF_8100_0000] = (0x100000).to_bytes(8, "little")

        # slab_caches 빈 리스트 초기화 (next = prev = self)
        slab_caches_addr = 0xFFFF_FFFF_8200_0000
        self._memory[slab_caches_addr] = slab_caches_addr.to_bytes(8, "little")  # next
        self._memory[slab_caches_addr + 8] = slab_caches_addr.to_bytes(
            8, "little"
        )  # prev

    # =========================================================================
    # Structure 메타정보
    # =========================================================================

    def sizeof(self, type_name: str) -> int:
        if type_name not in self._structs:
            raise KeyError(f"Unknown type: {type_name}")
        return self._structs[type_name][0]

    def offsetof(self, struct_name: str, member: str) -> int:
        if struct_name not in self._structs:
            raise KeyError(f"Unknown struct: {struct_name}")
        members = self._structs[struct_name][1]
        if member not in members:
            raise KeyError(f"Unknown member: {struct_name}.{member}")
        return members[member]

    def has_member(self, struct_name: str, member: str) -> bool:
        if struct_name not in self._structs:
            return False
        return member in self._structs[struct_name][1]

    # =========================================================================
    # Memory 읽기
    # =========================================================================

    def read_type(
        self, addr: int | str, type_name: str | None = None
    ) -> ctypes.Structure | int:
        original_addr = addr
        if isinstance(addr, str):
            resolved = self._symbols.get(addr)
            if resolved is None:
                raise KeyError(f"Unknown symbol: {addr}")
            original_addr = resolved

        if type_name == "struct page":
            # 페이지 캐시에서 찾기
            if original_addr in self._pages:
                page = self._pages[original_addr]
                page._base = original_addr
                page._struct = type_name
                return page
            # 새 페이지 생성
            page = MockPage()
            page._base = original_addr
            page._struct = type_name
            self._pages[original_addr] = page
            return page

        if type_name == "struct kmem_cache":
            if original_addr in self._caches:
                cache = self._caches[original_addr]
                cache._base = original_addr
                cache._struct = type_name
                return cache
            # 새 캐시 생성
            cache = MockKmemCache()
            cache._base = original_addr
            cache._struct = type_name
            self._caches[original_addr] = cache
            return cache

        if type_name == "struct slab":
            if original_addr in self._slabs:
                slab = self._slabs[original_addr]
                slab._base = original_addr
                slab._struct = type_name
                return slab
            # 새 slab 생성
            slab = MockSlab()
            slab._base = original_addr
            slab._struct = type_name
            self._slabs[original_addr] = slab
            return slab

        if type_name == "struct kmem_cache_cpu":
            if original_addr in self._cache_cpus:
                cpu = self._cache_cpus[original_addr]
                cpu._base = original_addr
                cpu._struct = type_name
                return cpu
            # 새 cpu slab 생성
            cpu = MockKmemCacheCpu()
            cpu._base = original_addr
            cpu._struct = type_name
            self._cache_cpus[original_addr] = cpu
            return cpu

        if type_name == "struct kmem_cache_node":
            if original_addr in self._cache_nodes:
                node = self._cache_nodes[original_addr]
                node._base = original_addr
                node._struct = type_name
                return node
            # 새 node 생성
            node = MockKmemCacheNode()
            node._base = original_addr
            node._struct = type_name
            self._cache_nodes[original_addr] = node
            return node

        if type_name == "struct track":
            if original_addr in self._tracks:
                track = self._tracks[original_addr]
                track._base = original_addr
                track._struct = type_name
                return track
            # 새 track 생성 (빈 tracking)
            track = MockTrack()
            track._base = original_addr
            track._struct = type_name
            self._tracks[original_addr] = track
            return track

        return 0

    def read_u8(self, addr: int | str) -> int:
        return self._read_int(addr, 1)

    def read_u16(self, addr: int | str) -> int:
        return self._read_int(addr, 2)

    def read_u32(self, addr: int | str) -> int:
        return self._read_int(addr, 4)

    def read_u64(self, addr: int | str) -> int:
        return self._read_int(addr, 8)

    def read_bytes(self, addr: int | str, size: int) -> bytes:
        if isinstance(addr, str):
            resolved = self._symbols.get(addr)
            if resolved is None:
                raise KeyError(f"Unknown symbol: {addr}")
            addr = resolved
        return self._memory.get(addr, b"\x00" * size)[:size]

    def read_pointer(self, addr: int | str) -> int:
        return self.read_u64(addr)

    def read_string(self, addr: int | str, max_len: int = 256) -> str:
        if isinstance(addr, str):
            resolved = self._symbols.get(addr)
            if resolved is None:
                raise KeyError(f"Unknown symbol: {addr}")
            addr = resolved
        # 문자열 캐시에서 찾기
        if addr in self._strings:
            return self._strings[addr][:max_len]
        # 메모리에서 읽기
        data = self.read_bytes(addr, max_len)
        null_idx = data.find(b"\x00")
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode("utf-8", errors="replace")

    def _read_int(self, addr: int | str, size: int) -> int:
        data = self.read_bytes(addr, size)
        return int.from_bytes(data, "little")

    # =========================================================================
    # Symbol
    # =========================================================================

    def symbol_to_addr(self, name: str) -> int | None:
        return self._symbols.get(name)

    def addr_to_symbol(self, addr: int) -> tuple[str, int] | None:
        # 간단한 구현: 정확히 일치하는 심볼만 반환
        for name, sym_addr in self._symbols.items():
            if sym_addr <= addr < sym_addr + 0x1000:
                return (name, addr - sym_addr)
        return None

    def is_symbol_valid(self, name: str) -> bool:
        return name in self._symbols

    # =========================================================================
    # Kernel Config
    # =========================================================================

    def get_enum(self, enum_name: str) -> dict[str, int] | None:
        return self._enums.get(enum_name)

    def get_enum_value(self, enum_name: str, member: str) -> int | None:
        enum = self._enums.get(enum_name)
        if enum is None:
            return None
        return enum.get(member)

    def get_config(self, config_name: str) -> bool | int | str | None:
        return self._configs.get(config_name)

    # =========================================================================
    # 주소 변환
    # =========================================================================

    def virt_to_phys(self, vaddr: int) -> int | None:
        # 간단한 구현: 상위 비트 제거
        if vaddr >= 0xFFFF_8000_0000_0000:
            return vaddr - 0xFFFF_8000_0000_0000
        return None

    def phys_to_virt(self, paddr: int) -> int:
        return paddr + 0xFFFF_8000_0000_0000

    # =========================================================================
    # Per-CPU
    # =========================================================================

    def per_cpu(self, symbol: str, cpu_id: int) -> int:
        base = self._symbols.get(symbol, 0)
        return base + cpu_id * 0x1000

    # =========================================================================
    # Container
    # =========================================================================

    def container_of(self, addr: int, struct_name: str, member: str) -> int:
        offset = self.offsetof(struct_name, member)
        return addr - offset

    # =========================================================================
    # 테스트 헬퍼
    # =========================================================================

    def register_page(self, pfn: int, flags: int = 0, **kwargs) -> MockPage:
        """테스트용 페이지 등록."""
        vmemmap_base = 0xFFFF_EA00_0000_0000
        page_size = ctypes.sizeof(MockPage)
        page_addr = vmemmap_base + pfn * page_size

        page = MockPage()
        page.flags = flags
        page.compound_head = kwargs.get("compound_head", 0)
        page.compound_order = kwargs.get("compound_order", 0)
        page._refcount.counter = kwargs.get("refcount", 1)
        page._mapcount.counter = kwargs.get("mapcount", 0)

        self._pages[page_addr] = page
        return page

    # =========================================================================
    # SLUB 테스트 헬퍼
    # =========================================================================

    def register_string(self, addr: int, value: str) -> None:
        """문자열 등록."""
        self._strings[addr] = value

    def register_kmem_cache(
        self,
        addr: int,
        name: str,
        object_size: int,
        size: int | None = None,
        offset: int = 0,
        inuse: int | None = None,
        random: int = 0,
        flags: int = 0,
    ) -> MockKmemCache:
        """
        kmem_cache 등록.

        Args:
            addr: cache 주소
            name: cache 이름
            object_size: 실제 object 크기
            size: 패딩 포함 크기 (기본: object_size)
            offset: freelist pointer offset
            inuse: tracking 오프셋용 (기본: object_size)
            random: FREELIST_HARDENED random 값
            flags: slab flags
        """
        if size is None:
            size = object_size
        if inuse is None:
            inuse = object_size

        cache = MockKmemCache()
        # name 문자열 저장 (별도 주소에)
        name_addr = addr + 0x1000  # cache 구조체 뒤에 name 저장
        self._strings[name_addr] = name
        cache.name = name_addr
        cache.object_size = object_size
        cache.size = size
        cache.offset = offset
        cache.inuse = inuse
        cache.random = random
        cache.flags = flags
        # list는 나중에 연결

        self._caches[addr] = cache
        return cache

    def register_slab(
        self,
        addr: int,
        cache_addr: int,
        objects: int,
        inuse: int,
        freelist: int = 0,
        frozen: int = 0,
    ) -> MockSlab:
        """
        slab 등록.

        Args:
            addr: slab 주소
            cache_addr: 소속 kmem_cache 주소
            objects: 총 object 수
            inuse: 사용 중인 object 수
            freelist: 첫 번째 free object 주소 (또는 encoded)
            frozen: frozen 플래그
        """
        slab = MockSlab()
        slab.slab_cache = cache_addr
        slab.objects = objects
        slab.inuse = inuse
        slab.freelist = freelist
        slab.frozen = frozen

        self._slabs[addr] = slab
        return slab

    def link_caches(self, cache_addrs: list[int]) -> None:
        """
        kmem_cache들을 slab_caches 리스트에 연결.

        Args:
            cache_addrs: cache 주소들의 리스트 (순서대로 연결)
        """
        slab_caches = self._symbols["slab_caches"]
        list_offset = self.offsetof("struct kmem_cache", "list")

        if not cache_addrs:
            # 빈 리스트
            self._memory[slab_caches] = slab_caches.to_bytes(8, "little")
            self._memory[slab_caches + 8] = slab_caches.to_bytes(8, "little")
            return

        # 첫 번째 cache의 list.next를 slab_caches.next로
        first_list = cache_addrs[0] + list_offset
        last_list = cache_addrs[-1] + list_offset

        # slab_caches -> first
        self._memory[slab_caches] = first_list.to_bytes(8, "little")
        # last -> slab_caches
        self._memory[last_list] = slab_caches.to_bytes(8, "little")
        self._memory[last_list + 8] = (
            cache_addrs[-2] + list_offset if len(cache_addrs) > 1 else slab_caches
        ).to_bytes(8, "little")

        # slab_caches.prev = last
        self._memory[slab_caches + 8] = last_list.to_bytes(8, "little")

        # 각 cache 연결
        for i, addr in enumerate(cache_addrs):
            list_addr = addr + list_offset
            # next
            if i < len(cache_addrs) - 1:
                next_addr = cache_addrs[i + 1] + list_offset
            else:
                next_addr = slab_caches
            # prev
            prev_addr = cache_addrs[i - 1] + list_offset if i > 0 else slab_caches

            self._memory[list_addr] = next_addr.to_bytes(8, "little")
            self._memory[list_addr + 8] = prev_addr.to_bytes(8, "little")

    def setup_freelist(
        self,
        slab: MockSlab,
        cache: MockKmemCache,
        free_indices: list[int],
        slab_virt_addr: int,
        hardened: bool = False,
    ) -> None:
        """
        Slab의 freelist 체인 설정.

        Args:
            slab: MockSlab 인스턴스
            cache: MockKmemCache 인스턴스
            free_indices: free object 인덱스 리스트 (순서대로 체인)
            slab_virt_addr: slab의 가상 주소 (object 시작점)
            hardened: FREELIST_HARDENED 인코딩 적용 여부
        """
        if not free_indices:
            slab.freelist = 0
            return

        obj_size = cache.size
        fp_offset = cache.offset
        random = cache.random

        def encode_ptr(ptr: int, ptr_addr: int) -> int:
            if not hardened:
                return ptr
            # freelist_ptr_encode: ptr ^ random ^ swab64(ptr_addr)
            swab = int.from_bytes(ptr_addr.to_bytes(8, "little"), "big")
            return ptr ^ random ^ swab

        # 첫 번째 free object
        first_obj = slab_virt_addr + free_indices[0] * obj_size
        # slab.freelist는 첫 번째 free object를 가리킴 (인코딩 필요 시)
        slab_freelist_addr = slab._base + self.offsetof("struct slab", "freelist")
        slab.freelist = encode_ptr(first_obj, slab_freelist_addr)

        # 체인 연결
        for i, idx in enumerate(free_indices):
            obj_addr = slab_virt_addr + idx * obj_size
            fp_addr = obj_addr + fp_offset

            if i < len(free_indices) - 1:
                next_obj = slab_virt_addr + free_indices[i + 1] * obj_size
                encoded = encode_ptr(next_obj, fp_addr)
            else:
                encoded = encode_ptr(0, fp_addr)  # 마지막은 NULL

            self._memory[fp_addr] = encoded.to_bytes(8, "little")

    # =========================================================================
    # Tracking 테스트 헬퍼
    # =========================================================================

    def register_object_track(
        self,
        obj_addr: int,
        cache: MockKmemCache,
        alloc_track: dict | None = None,
        free_track: dict | None = None,
    ) -> None:
        """
        Object의 tracking 정보 설정.

        Args:
            obj_addr: object 시작 주소
            cache: kmem_cache (inuse, flags 필요)
            alloc_track: {"addr": int, "handle": int, "cpu": int, "pid": int, "when": int}
            free_track: 동일 형식
        """
        # Track 오프셋 계산 (SLAB_RED_ZONE이면 inuse + 8, 아니면 inuse)
        slab_red_zone = self._enums["slabflags"]["SLAB_RED_ZONE"]
        info_end = cache.inuse + 8 if cache.flags & slab_red_zone else cache.inuse

        track_size = ctypes.sizeof(MockTrack)

        # alloc_track (TRACK_ALLOC = 0)
        if alloc_track:
            alloc_addr = obj_addr + info_end
            track = MockTrack()
            track.addr = alloc_track.get("addr", 0)
            track.handle = alloc_track.get("handle", 0)
            track.cpu = alloc_track.get("cpu", 0)
            track.pid = alloc_track.get("pid", 0)
            track.when = alloc_track.get("when", 0)
            self._tracks[alloc_addr] = track

        # free_track (TRACK_FREE = 1)
        if free_track:
            free_addr = obj_addr + info_end + track_size
            track = MockTrack()
            track.addr = free_track.get("addr", 0)
            track.handle = free_track.get("handle", 0)
            track.cpu = free_track.get("cpu", 0)
            track.pid = free_track.get("pid", 0)
            track.when = free_track.get("when", 0)
            self._tracks[free_addr] = track

    def register_stack_depot_entry(
        self,
        handle: int,
        stack_addrs: list[int],
    ) -> None:
        """
        Stack depot 엔트리 등록.

        Args:
            handle: depot_stack_handle_t
            stack_addrs: 스택 주소 목록
        """
        self._stack_depot[handle] = stack_addrs

    def register_symbol_addr(self, addr: int, name: str, offset: int = 0) -> None:
        """
        주소에 대한 심볼 정보 등록 (addr_to_symbol용).

        Args:
            addr: 주소
            name: 심볼 이름
            offset: 오프셋 (기본 0)
        """
        if not hasattr(self, "_addr_to_symbol"):
            self._addr_to_symbol: dict[int, tuple[str, int]] = {}
        self._addr_to_symbol[addr] = (name, offset)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_backend() -> MockDIBackend:
    """Mock backend fixture."""
    return MockDIBackend()


@pytest.fixture
def struct_helper(mock_backend: MockDIBackend):
    """StructHelper fixture."""
    from di_memory.core.struct_helper import StructHelper

    return StructHelper(mock_backend)


@pytest.fixture
def address_translator(mock_backend: MockDIBackend):
    """AddressTranslator fixture."""
    from di_memory.core.address_translator import AddressTranslator

    return AddressTranslator(mock_backend)


@pytest.fixture
def kernel_resolver(mock_backend: MockDIBackend):
    """KernelResolver fixture."""
    from di_memory.core.kernel_resolver import KernelResolver

    return KernelResolver(mock_backend)


@pytest.fixture
def page_analyzer(
    mock_backend: MockDIBackend,
    struct_helper,
    address_translator,
    kernel_resolver,
):
    """PageAnalyzer fixture."""
    from di_memory.analyzers.page import PageAnalyzer

    return PageAnalyzer(
        backend=mock_backend,
        structs=struct_helper,
        addr=address_translator,
        symbols=kernel_resolver,
    )


@pytest.fixture
def page_flags_helper(kernel_resolver):
    """PageFlagsHelper fixture."""
    from di_memory.utils.flags import PageFlagsHelper

    return PageFlagsHelper(kernel_resolver)


@pytest.fixture
def slub_analyzer(
    mock_backend: MockDIBackend,
    struct_helper,
    address_translator,
    kernel_resolver,
):
    """SlubAnalyzer fixture."""
    from di_memory.analyzers.slub import SlubAnalyzer

    return SlubAnalyzer(
        backend=mock_backend,
        structs=struct_helper,
        addr=address_translator,
        symbols=kernel_resolver,
    )
