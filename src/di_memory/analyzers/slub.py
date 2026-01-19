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
        return bool(self._symbols.get_config("CONFIG_SLAB_FREELIST_HARDENED"))

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

    def _get_slab_cache(self, slab: ctypes.Structure) -> ctypes.Structure:
        """Slab이 속한 kmem_cache 반환."""
        return self._structs.read(slab.slab_cache, "struct kmem_cache")

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

    def iter_partial_slabs(self, cache: ctypes.Structure) -> Iterator[ctypes.Structure]:
        """
        Cache의 partial slab 리스트 순회.

        per-node partial 리스트를 순회.

        Args:
            cache: struct kmem_cache

        Yields:
            struct slab
        """
        # 간단 구현: node[0]의 partial 리스트만 순회
        # 실제로는 모든 node를 순회해야 함
        if not self._backend.has_member("struct kmem_cache", "node"):
            return

        node_ptr = self._backend.read_pointer(
            cache._base + self._backend.offsetof("struct kmem_cache", "node")
        )
        if node_ptr == 0:
            return

        node = self._structs.read(node_ptr, "struct kmem_cache_node")
        partial_offset = self._backend.offsetof("struct kmem_cache_node", "partial")
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

    def iter_cpu_slabs(
        self, cache: ctypes.Structure
    ) -> Iterator[tuple[int, ctypes.Structure | None]]:
        """
        Per-CPU slab 순회.

        Args:
            cache: struct kmem_cache

        Yields:
            (cpu_id, struct slab or None) 튜플
        """
        # 간단 구현: CPU 0만 순회
        # 실제로는 nr_cpu_ids 만큼 순회해야 함
        cpu_slab_addr = self._backend.per_cpu(cache.cpu_slab, 0)
        cpu_slab = self._structs.read(cpu_slab_addr, "struct kmem_cache_cpu")

        slab_addr = cpu_slab.slab
        if slab_addr != 0:
            slab = self._structs.read(slab_addr, "struct slab")
            yield (0, slab)
        else:
            yield (0, None)

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
        while current != 0 and current not in seen:
            seen.add(current)

            # 디코딩
            decoded = self._decode_freeptr(cache, current, ptr_addr)
            if decoded == 0:
                break

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
        return obj_addr in set(self.iter_free_objects(slab))

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
    # Freelist 검증 및 Corruption 역추적
    # =========================================================================

    def validate_freelist(self, slab: ctypes.Structure) -> dict:
        """
        Freelist 무결성 검증.

        Args:
            slab: struct slab

        Returns:
            {
                "valid": bool,
                "free_count": int,
                "expected_free": int,
                "errors": list[dict],
            }
        """
        cache = self._get_slab_cache(slab)
        fp_offset = cache.offset

        freelist_offset = self._backend.offsetof("struct slab", "freelist")
        ptr_addr = slab._base + freelist_offset
        current = slab.freelist

        errors: list[dict] = []
        seen: set[int] = set()
        free_count = 0

        while current != 0:
            if current in seen:
                errors.append(
                    {
                        "type": "cycle",
                        "ptr_addr": ptr_addr,
                        "encoded_value": current,
                        "details": f"Cycle detected at {hex(current)}",
                    }
                )
                break

            seen.add(current)

            decoded = self._decode_freeptr(cache, current, ptr_addr)

            if decoded != 0 and not self._is_valid_object_addr(decoded, slab, cache):
                base = self.slab_to_virt(slab)
                end = base + slab.objects * cache.size
                errors.append(
                    {
                        "type": "out_of_bounds",
                        "ptr_addr": ptr_addr,
                        "encoded_value": current,
                        "decoded_value": decoded,
                        "details": f"Decoded {hex(decoded)} outside [{hex(base)}, {hex(end)})",
                    }
                )
                break

            if decoded != 0:
                free_count += 1

            ptr_addr = decoded + fp_offset if decoded != 0 else 0
            current = self._backend.read_pointer(ptr_addr) if decoded != 0 else 0

        expected_free = slab.objects - slab.inuse

        if free_count != expected_free and not errors:
            errors.append(
                {
                    "type": "count_mismatch",
                    "ptr_addr": 0,
                    "encoded_value": 0,
                    "details": f"Free count {free_count} != expected {expected_free}",
                }
            )

        return {
            "valid": len(errors) == 0,
            "free_count": free_count,
            "expected_free": expected_free,
            "errors": errors,
        }

    def trace_corrupted_freeptr(
        self,
        cache: ctypes.Structure,
        ptr_addr: int,
        encoded_value: int,
    ) -> dict:
        """
        Corrupted freelist 포인터 분석.

        FREELIST_HARDENED 환경에서 corruption 발생 시:
        - 원본 값 추정 (bitflip 분석)
        - 예상되는 올바른 encoded 값 계산
        - corruption 패턴 분석

        Args:
            cache: struct kmem_cache
            ptr_addr: 포인터가 저장된 주소
            encoded_value: 읽은 (corrupted) 인코딩 값

        Returns:
            {
                "ptr_addr": int,
                "encoded_value": int,
                "decoded_value": int,
                "expected_range": tuple[int, int],
                "analysis": dict,
                "likely_cause": str,
            }
        """
        decoded = self._decode_freeptr(cache, encoded_value, ptr_addr)

        # 유효한 object 범위 계산 (cache의 일반적인 slab 기준)
        # 실제로는 slab 정보가 필요하지만, 여기서는 일반적인 범위 추정
        page_size = self._addr.page_size
        expected_base = ptr_addr & ~(page_size - 1)  # 페이지 정렬
        expected_end = expected_base + page_size

        # Bitflip 분석
        analysis = self._analyze_bitflip(decoded, (expected_base, expected_end))

        # 원인 추정
        likely_cause = "unknown"
        if analysis["is_bitflip"]:
            likely_cause = "bitflip"
        elif decoded == 0xDEAD_BEEF or decoded == 0xDEAD_DEAD:
            likely_cause = "use_after_free"
        elif decoded > 0xFFFF_FFFF_FFFF_0000:
            likely_cause = "overflow"

        return {
            "ptr_addr": ptr_addr,
            "encoded_value": encoded_value,
            "decoded_value": decoded,
            "expected_range": (expected_base, expected_end),
            "analysis": analysis,
            "likely_cause": likely_cause,
        }

    def _analyze_bitflip(self, corrupted: int, valid_range: tuple[int, int]) -> dict:
        """
        단일 bitflip으로 valid 값이 되는지 분석.

        Args:
            corrupted: corrupted 값
            valid_range: (start, end) 유효 범위

        Returns:
            {
                "is_bitflip": bool,
                "candidates": list[dict],
            }
        """
        candidates: list[dict] = []
        start, end = valid_range

        for bit in range(64):
            flipped = corrupted ^ (1 << bit)
            if start <= flipped < end:
                candidates.append({"value": flipped, "bit": bit})

        return {
            "is_bitflip": len(candidates) > 0,
            "candidates": candidates,
        }

    def validate_cache_freelists(self, cache: ctypes.Structure) -> dict:
        """
        Cache의 모든 slab freelist 검증.

        Args:
            cache: struct kmem_cache

        Returns:
            {
                "cache_name": str,
                "total_slabs": int,
                "corrupted_slabs": int,
                "errors": list[dict],
            }
        """
        cache_name = self.get_cache_name(cache)
        total_slabs = 0
        corrupted_slabs = 0
        all_errors: list[dict] = []

        for slab in self.iter_slabs(cache):
            total_slabs += 1
            result = self.validate_freelist(slab)
            if not result["valid"]:
                corrupted_slabs += 1
                for err in result["errors"]:
                    err["slab_addr"] = slab._base
                    all_errors.append(err)

        return {
            "cache_name": cache_name,
            "total_slabs": total_slabs,
            "corrupted_slabs": corrupted_slabs,
            "errors": all_errors,
        }

    # =========================================================================
    # 주소 역추적
    # =========================================================================

    def find_owning_cache(self, addr: int) -> tuple | None:
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
        validation = self.validate_freelist(slab)
        return {
            "address": slab._base,
            "virt_addr": self.slab_to_virt(slab),
            "objects": slab.objects,
            "inuse": slab.inuse,
            "frozen": bool(slab.frozen),
            "freelist_valid": validation["valid"],
        }
