"""SLUB allocator 분석기."""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from typing import TYPE_CHECKING

from di_memory.analyzers.base import BaseAnalyzer

if TYPE_CHECKING:
    from di_memory.backend.protocol import DIBackend
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.stackdepot import StackDepotResolver
    from di_memory.core.struct_helper import StructHelper


class SlubAnalyzer(BaseAnalyzer):
    """SLUB allocator 분석기 (Linux 6.12+ 기반)."""

    def __init__(
        self,
        backend: DIBackend,
        structs: StructHelper,
        addr: AddressTranslator,
        symbols: KernelResolver,
    ) -> None:
        """
        SlubAnalyzer 초기화.

        Args:
            backend: DIBackend 인스턴스
            structs: StructHelper 인스턴스
            addr: AddressTranslator 인스턴스
            symbols: KernelResolver 인스턴스
        """
        super().__init__(backend, structs, addr, symbols)
        self._stack_depot: StackDepotResolver | None = None

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def slab_caches_head(self) -> int:
        """slab_caches 심볼 주소."""
        addr = self._symbols.to_addr("slab_caches")
        if addr is None:
            raise ValueError("slab_caches symbol not found")
        return addr

    @property
    def is_hardened(self) -> bool:
        """CONFIG_SLAB_FREELIST_HARDENED 활성화 여부."""
        return self._symbols.is_config_enabled("CONFIG_SLAB_FREELIST_HARDENED")

    @property
    def has_stackdepot(self) -> bool:
        """CONFIG_STACKDEPOT 활성화 여부."""
        return self._symbols.is_config_enabled("CONFIG_STACKDEPOT")

    @property
    def stack_depot(self) -> StackDepotResolver | None:
        """StackDepotResolver 인스턴스 (lazy init)."""
        if self._stack_depot is None and self.has_stackdepot:
            from di_memory.core.stackdepot import StackDepotResolver

            self._stack_depot = StackDepotResolver(self._backend, self._symbols)
        return self._stack_depot

    # =========================================================================
    # SLAB Flags
    # =========================================================================

    def _get_slab_flag(self, flag_name: str) -> int:
        """
        SLAB 플래그 값 조회 (캐시됨).

        Args:
            flag_name: 플래그 이름 (예: "SLAB_STORE_USER", "SLAB_RED_ZONE")

        Returns:
            플래그 값 또는 0
        """
        value = self._symbols.get_enum_value("slabflags", flag_name)
        return value if value is not None else 0

    def _test_slab_flag(self, cache: ctypes.Structure, flag_name: str) -> bool:
        """Cache에 특정 SLAB 플래그가 설정되어 있는지 확인."""
        flag = self._get_slab_flag(flag_name)
        return bool(cache.flags & flag) if flag else False

    # =========================================================================
    # Cache 조회/순회
    # =========================================================================

    def iter_caches(self) -> Iterator[ctypes.Structure]:
        """
        모든 kmem_cache 순회.

        slab_caches 리스트를 순회하며 각 kmem_cache를 반환.

        Yields:
            struct kmem_cache
        """
        yield from self._structs.list_for_each_entry(
            self.slab_caches_head, "struct kmem_cache", "list"
        )

    def get_cache(self, name: str) -> ctypes.Structure | None:
        """
        이름으로 kmem_cache 조회.

        Args:
            name: cache 이름 (예: "kmalloc-128", "task_struct")

        Returns:
            struct kmem_cache 또는 None
        """
        for cache in self.iter_caches():
            cache_name = self._backend.read_string(cache.name)
            if cache_name == name:
                return cache
        return None

    def get_cache_by_addr(self, addr: int) -> ctypes.Structure | None:
        """
        주소로 kmem_cache 조회 (검증용).

        Args:
            addr: kmem_cache 주소

        Returns:
            struct kmem_cache 또는 None (유효하지 않은 경우)
        """
        for cache in self.iter_caches():
            if cache._base == addr:
                return cache
        return None

    def get_cache_name(self, cache: ctypes.Structure) -> str:
        """
        Cache 이름 반환.

        Args:
            cache: struct kmem_cache

        Returns:
            cache 이름
        """
        return self._backend.read_string(cache.name)

    # =========================================================================
    # Slab 조회/순회
    # =========================================================================

    def get_slab(self, page: ctypes.Structure) -> ctypes.Structure:
        """
        Page에서 slab 구조체 조회.

        Linux 6.12+에서 struct page와 struct slab은 동일 주소.

        Args:
            page: struct page

        Returns:
            struct slab
        """
        return self._structs.read(page._base, "struct slab")

    def get_slab_by_addr(self, addr: int) -> ctypes.Structure | None:
        """
        주소로 slab 구조체 조회.

        Args:
            addr: slab 구조체 주소

        Returns:
            struct slab 또는 None (읽기 실패 시)
        """
        return self._structs.read(addr, "struct slab")

    def _get_slab_cache(self, slab: ctypes.Structure) -> ctypes.Structure:
        """Slab이 속한 kmem_cache 반환."""
        return self._structs.read(slab.slab_cache, "struct kmem_cache")

    def get_slab_cache(self, slab: ctypes.Structure) -> ctypes.Structure:
        """
        Slab이 속한 kmem_cache 조회.

        Args:
            slab: struct slab

        Returns:
            struct kmem_cache
        """
        return self._get_slab_cache(slab)

    def slab_to_virt(self, slab: ctypes.Structure) -> int:
        """
        Slab의 시작 가상 주소 계산.

        Args:
            slab: struct slab

        Returns:
            slab 내 첫 object의 가상 주소
        """
        # slab 주소에서 struct page 주소 추출 (동일)
        pfn = self._addr.page_to_pfn(slab._base)
        paddr = self._addr.pfn_to_phys(pfn)
        return self._addr.phys_to_virt(paddr)

    @property
    def nr_node_ids(self) -> int:
        """NUMA node 수 (nr_node_ids 또는 기본값 1)."""
        addr = self._symbols.to_addr("nr_node_ids")
        if addr is not None:
            return self._backend.read_u32(addr)
        return 1  # UMA 시스템

    def iter_partial_slabs(self, cache: ctypes.Structure) -> Iterator[ctypes.Structure]:
        """
        Cache의 partial slab 리스트 순회.

        모든 NUMA node의 partial 리스트를 순회.

        Args:
            cache: struct kmem_cache

        Yields:
            struct slab
        """
        if not self._backend.has_member("struct kmem_cache", "node"):
            return

        node_array_addr = cache._base + self._backend.offsetof(
            "struct kmem_cache", "node"
        )
        partial_offset = self._backend.offsetof("struct kmem_cache_node", "partial")
        ptr_size = 8  # 64-bit pointer

        for nid in range(self.nr_node_ids):
            node_ptr = self._backend.read_pointer(node_array_addr + nid * ptr_size)
            if node_ptr == 0:
                continue

            node = self._structs.read(node_ptr, "struct kmem_cache_node")
            partial_head = node._base + partial_offset

            yield from self._structs.list_for_each_entry(
                partial_head, "struct slab", "slab_list"
            )

    def iter_slabs(self, cache: ctypes.Structure) -> Iterator[ctypes.Structure]:
        """
        Cache의 모든 slab 순회 (partial + cpu).

        Args:
            cache: struct kmem_cache

        Yields:
            struct slab
        """
        # Partial slabs
        yield from self.iter_partial_slabs(cache)

        # CPU slabs
        for _cpu_id, slab in self.iter_cpu_slabs(cache):
            if slab is not None:
                yield slab

    @property
    def nr_cpu_ids(self) -> int:
        """CPU 수 (nr_cpu_ids 또는 기본값 1)."""
        addr = self._symbols.to_addr("nr_cpu_ids")
        if addr is not None:
            return self._backend.read_u32(addr)
        return 1

    def iter_cpu_slabs(
        self, cache: ctypes.Structure
    ) -> Iterator[tuple[int, ctypes.Structure | None]]:
        """
        Per-CPU slab 순회.

        모든 CPU의 현재 slab을 순회.

        Args:
            cache: struct kmem_cache

        Yields:
            (cpu_id, struct slab or None) 튜플
        """
        for cpu_id in range(self.nr_cpu_ids):
            cpu_slab_addr = self._backend.per_cpu(cache.cpu_slab, cpu_id)
            cpu_slab = self._structs.read(cpu_slab_addr, "struct kmem_cache_cpu")

            slab_addr = cpu_slab.slab
            if slab_addr != 0:
                slab = self._structs.read(slab_addr, "struct slab")
                yield (cpu_id, slab)
            else:
                yield (cpu_id, None)

    # =========================================================================
    # Object 관련
    # =========================================================================

    def iter_objects(self, slab: ctypes.Structure) -> Iterator[int]:
        """
        Slab 내 모든 object 주소 순회.

        위치 기반으로 모든 object 주소를 계산.

        Args:
            slab: struct slab

        Yields:
            object 가상 주소
        """
        cache = self._get_slab_cache(slab)
        base = self.slab_to_virt(slab)
        obj_size = cache.size
        count = slab.objects

        for i in range(count):
            yield base + i * obj_size

    def iter_free_objects(self, slab: ctypes.Structure) -> Iterator[int]:
        """
        Slab의 free object 순회 (freelist 체인).

        FREELIST_HARDENED 환경에서는 디코딩 수행.

        Args:
            slab: struct slab

        Yields:
            free object 가상 주소
        """
        cache = self._get_slab_cache(slab)
        fp_offset = cache.offset

        # freelist 시작
        freelist_offset = self._backend.offsetof("struct slab", "freelist")
        ptr_addr = slab._base + freelist_offset
        current = slab.freelist

        seen: set[int] = set()
        while current != 0:
            # 디코딩
            decoded = self._decode_freeptr(cache, current, ptr_addr)
            if decoded == 0:
                break

            # cycle 검사 (decoded 기준)
            if decoded in seen:
                break
            seen.add(decoded)

            # 유효성 검사
            if not self._is_valid_object_addr(decoded, slab, cache):
                break

            yield decoded

            # 다음 포인터 읽기
            ptr_addr = decoded + fp_offset
            current = self._backend.read_pointer(ptr_addr)

    def iter_inuse_objects(self, slab: ctypes.Structure) -> Iterator[int]:
        """
        Slab의 사용 중인 object 순회.

        Args:
            slab: struct slab

        Yields:
            inuse object 가상 주소
        """
        free_set = set(self.iter_free_objects(slab))
        for obj in self.iter_objects(slab):
            if obj not in free_set:
                yield obj

    def is_object_free(self, slab: ctypes.Structure, obj_addr: int) -> bool:
        """
        Object가 free 상태인지 확인.

        Args:
            slab: struct slab
            obj_addr: object 주소

        Returns:
            free 여부
        """
        return any(free_obj == obj_addr for free_obj in self.iter_free_objects(slab))

    def get_object_index(self, slab: ctypes.Structure, obj_addr: int) -> int | None:
        """
        Object의 slab 내 인덱스 반환.

        Args:
            slab: struct slab
            obj_addr: object 주소

        Returns:
            인덱스 또는 None (유효하지 않은 주소)
        """
        cache = self._get_slab_cache(slab)
        base = self.slab_to_virt(slab)

        if obj_addr < base:
            return None

        offset = obj_addr - base
        index = offset // cache.size

        if index >= slab.objects:
            return None

        # 정확히 object 시작 주소인지 확인
        if base + index * cache.size != obj_addr:
            return None

        return index

    # =========================================================================
    # FREELIST_HARDENED 디코딩
    # =========================================================================

    def _swab64(self, val: int) -> int:
        """64비트 바이트 순서 역전 (big-endian swap)."""
        return int.from_bytes(val.to_bytes(8, "little"), "big")

    def _decode_freeptr(
        self, cache: ctypes.Structure, encoded: int, ptr_addr: int
    ) -> int:
        """
        FREELIST_HARDENED freelist 포인터 디코딩.

        디코딩 공식: decoded = encoded ^ random ^ swab64(ptr_addr)

        Args:
            cache: kmem_cache (random 값 보유)
            encoded: 인코딩된 포인터 값
            ptr_addr: 포인터가 저장된 주소

        Returns:
            디코딩된 실제 포인터 값
        """
        if not self.is_hardened:
            return encoded

        random = cache.random
        swab_addr = self._swab64(ptr_addr)
        return encoded ^ random ^ swab_addr

    def _encode_freeptr(self, cache: ctypes.Structure, ptr: int, ptr_addr: int) -> int:
        """
        FREELIST_HARDENED freelist 포인터 인코딩.

        XOR 연산은 대칭이므로 디코딩과 동일한 로직.

        Args:
            cache: kmem_cache
            ptr: 실제 포인터 값
            ptr_addr: 포인터가 저장될 주소

        Returns:
            인코딩된 포인터 값
        """
        return self._decode_freeptr(cache, ptr, ptr_addr)

    def _is_valid_object_addr(
        self, addr: int, slab: ctypes.Structure, cache: ctypes.Structure
    ) -> bool:
        """Object 주소가 slab 범위 내인지 확인."""
        base = self.slab_to_virt(slab)
        end = base + slab.objects * cache.size
        return base <= addr < end

    # =========================================================================
    # 주소 역추적
    # =========================================================================

    def find_owning_cache(
        self, addr: int
    ) -> tuple[ctypes.Structure, ctypes.Structure, int, int] | None:
        """
        주소가 속한 slab cache 찾기.

        Args:
            addr: 검색할 메모리 주소

        Returns:
            (cache, slab, obj_addr, obj_index) 또는 None
            - cache: struct kmem_cache
            - slab: struct slab
            - obj_addr: object 시작 주소
            - obj_index: slab 내 object 인덱스
        """
        # 1. addr -> page
        page = self._addr.virt_to_page(addr)
        if page is None:
            return None

        # 2. PG_slab 플래그 확인
        pg_slab_bit = self._symbols.get_enum_value("pageflags", "PG_slab")
        if pg_slab_bit is None:
            return None
        if not (page.flags & (1 << pg_slab_bit)):
            return None

        # 3. slab 구조체 얻기
        slab = self.get_slab(page)
        cache = self._get_slab_cache(slab)

        # 4. object 주소 정렬
        base = self.slab_to_virt(slab)
        if addr < base:
            return None

        offset = addr - base
        obj_index = offset // cache.size

        if obj_index >= slab.objects:
            return None

        obj_addr = base + obj_index * cache.size

        return (cache, slab, obj_addr, obj_index)

    def addr_to_object(self, addr: int) -> int | None:
        """
        주소를 object 시작 주소로 정렬.

        Args:
            addr: 메모리 주소

        Returns:
            object 시작 주소 또는 None
        """
        result = self.find_owning_cache(addr)
        return result[2] if result else None

    # =========================================================================
    # 정보/통계
    # =========================================================================

    def get_cache_info(self, cache: ctypes.Structure) -> dict:
        """
        Cache 기본 정보.

        Args:
            cache: struct kmem_cache

        Returns:
            cache 정보 dict
        """
        return {
            "name": self.get_cache_name(cache),
            "address": cache._base,
            "object_size": cache.object_size,
            "size": cache.size,
            "offset": cache.offset,
            "flags": cache.flags,
            "random": cache.random if self.is_hardened else None,
        }

    def get_slab_info(self, slab: ctypes.Structure) -> dict:
        """
        Slab 기본 정보.

        Args:
            slab: struct slab

        Returns:
            slab 정보 dict
        """
        return {
            "address": slab._base,
            "virt_addr": self.slab_to_virt(slab),
            "objects": slab.objects,
            "inuse": slab.inuse,
            "frozen": bool(slab.frozen),
        }

    # =========================================================================
    # Tracking (CONFIG_SLUB_DEBUG)
    # =========================================================================

    def is_tracking_enabled(self, cache: ctypes.Structure) -> bool:
        """
        Cache에 tracking 활성화 여부.

        SLAB_STORE_USER 플래그 확인.

        Args:
            cache: struct kmem_cache

        Returns:
            tracking 활성화 여부
        """
        return self._test_slab_flag(cache, "SLAB_STORE_USER")

    def _get_info_end(self, cache: ctypes.Structure) -> int:
        """
        Object 내 metadata 시작 오프셋.

        SLAB_RED_ZONE이면 inuse + sizeof(void*), 아니면 inuse.
        """
        if self._test_slab_flag(cache, "SLAB_RED_ZONE"):
            # redzone은 sizeof(void*) 크기
            ptr_size = 8  # 64-bit 시스템 가정
            return cache.inuse + ptr_size
        return cache.inuse

    def _get_track_size(self) -> int:
        """struct track 크기."""
        return self._backend.sizeof("struct track")

    def _get_track_offset(self, cache: ctypes.Structure, track_item: int) -> int:
        """
        Object 내 track 구조체 오프셋.

        Args:
            cache: kmem_cache
            track_item: 0=TRACK_ALLOC, 1=TRACK_FREE

        Returns:
            track 오프셋
        """
        info_end = self._get_info_end(cache)
        track_size = self._get_track_size()
        return info_end + track_item * track_size

    def get_alloc_track(self, cache: ctypes.Structure, obj_addr: int) -> dict | None:
        """
        Object의 할당 추적 정보.

        Args:
            cache: struct kmem_cache
            obj_addr: object 시작 주소

        Returns:
            {
                "addr": int,        # 호출 주소
                "handle": int,      # stack depot handle
                "cpu": int,         # 할당 CPU
                "pid": int,         # 할당 PID
                "when": int,        # jiffies 타임스탬프
                "stack": list[str], # resolved 스택 트레이스
            } 또는 None (tracking 미활성화)
        """
        if not self.is_tracking_enabled(cache):
            return None
        return self._read_track(cache, obj_addr, 0)  # TRACK_ALLOC

    def get_free_track(self, cache: ctypes.Structure, obj_addr: int) -> dict | None:
        """
        Object의 해제 추적 정보.

        반환 형식은 get_alloc_track과 동일.
        free된 적 없으면 addr/handle이 0.

        Args:
            cache: struct kmem_cache
            obj_addr: object 시작 주소

        Returns:
            track 정보 dict 또는 None
        """
        if not self.is_tracking_enabled(cache):
            return None
        return self._read_track(cache, obj_addr, 1)  # TRACK_FREE

    def get_object_tracks(self, cache: ctypes.Structure, obj_addr: int) -> dict:
        """
        Object의 alloc/free 추적 정보 모두 반환.

        Args:
            cache: struct kmem_cache
            obj_addr: object 시작 주소

        Returns:
            {
                "tracking_enabled": bool,
                "alloc": dict | None,
                "free": dict | None,
            }
        """
        return {
            "tracking_enabled": self.is_tracking_enabled(cache),
            "alloc": self.get_alloc_track(cache, obj_addr),
            "free": self.get_free_track(cache, obj_addr),
        }

    def _read_track(
        self, cache: ctypes.Structure, obj_addr: int, track_item: int
    ) -> dict:
        """
        Track 구조체 읽기 및 스택 resolve.

        Args:
            cache: kmem_cache
            obj_addr: object 주소
            track_item: 0=TRACK_ALLOC, 1=TRACK_FREE

        Returns:
            track 정보 dict
        """
        offset = self._get_track_offset(cache, track_item)
        track_addr = obj_addr + offset
        track = self._structs.read(track_addr, "struct track")

        # 스택 resolve
        stack: list[str] = []
        handle = getattr(track, "handle", 0)
        if self.has_stackdepot and handle:
            stack = self._resolve_stack_depot(handle)
        elif track.addr:
            # 단일 주소만 있는 경우
            symbol = self._symbols.to_symbol(track.addr)
            if symbol:
                name, sym_offset = symbol
                stack = [f"{name}+{hex(sym_offset)}"]

        return {
            "addr": track.addr,
            "handle": handle,
            "cpu": track.cpu,
            "pid": track.pid,
            "when": track.when,
            "stack": stack,
        }

    def _resolve_stack_depot(self, handle: int) -> list[str]:
        """
        Stack depot 핸들에서 스택 resolve.

        Args:
            handle: depot_stack_handle_t

        Returns:
            resolved 스택 문자열 리스트
        """
        if self.stack_depot is None:
            return []
        return self.stack_depot.resolve_stack(handle)
