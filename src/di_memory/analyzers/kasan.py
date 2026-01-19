"""KASAN SW_TAGS (AArch64 TBI) 분석기 - Linux 6.12+."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from di_memory.analyzers.base import BaseAnalyzer
from di_memory.utils.constants import (
    KASAN_BUG_OUT_OF_BOUNDS,
    KASAN_BUG_TAG_MISMATCH,
    KASAN_BUG_USE_AFTER_FREE,
    KASAN_GRANULE_MASK,
    KASAN_GRANULE_SIZE,
    KASAN_SHADOW_SCALE_SHIFT,
    KASAN_TAG_INVALID,
    KASAN_TAG_KERNEL,
    KASAN_TAG_MASK,
    KASAN_TAG_MAX,
    KASAN_TAG_MIN,
    KASAN_TAG_SHIFT,
)

if TYPE_CHECKING:
    import ctypes

    from di_memory.backend.protocol import DIBackend
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.stackdepot import StackDepotResolver
    from di_memory.core.struct_helper import StructHelper


class KasanAnalyzer(BaseAnalyzer):
    """KASAN SW_TAGS (AArch64 TBI) 메모리 분석기.

    AArch64 TBI(Top Byte Ignore) 기능을 활용한 software tag-based KASAN 분석.
    포인터 상위 1바이트에 태그를 저장하고, shadow memory에 메모리 태그를 관리.

    Attributes:
        TAG_SHIFT: 포인터 태그 비트 위치 (56)
        TAG_MASK: 태그 마스크 (0xFF << 56)
        SHADOW_SCALE_SHIFT: Shadow 비율 (4, 16:1)
        GRANULE_SIZE: 태그 단위 크기 (16 bytes)
    """

    # Constants
    TAG_SHIFT = KASAN_TAG_SHIFT
    TAG_MASK = KASAN_TAG_MASK
    SHADOW_SCALE_SHIFT = KASAN_SHADOW_SCALE_SHIFT
    GRANULE_SIZE = KASAN_GRANULE_SIZE
    GRANULE_MASK = KASAN_GRANULE_MASK

    # Tag values
    TAG_MIN = KASAN_TAG_MIN
    TAG_MAX = KASAN_TAG_MAX
    TAG_INVALID = KASAN_TAG_INVALID
    TAG_KERNEL = KASAN_TAG_KERNEL

    def __init__(
        self,
        backend: DIBackend,
        structs: StructHelper,
        addr: AddressTranslator,
        symbols: KernelResolver,
    ) -> None:
        """
        KasanAnalyzer 초기화.

        Args:
            backend: DIBackend 인스턴스
            structs: StructHelper 인스턴스
            addr: AddressTranslator 인스턴스
            symbols: KernelResolver 인스턴스
        """
        super().__init__(backend, structs, addr, symbols)
        self._shadow_offset: int | None = None
        self._stack_depot: StackDepotResolver | None = None

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def is_enabled(self) -> bool:
        """CONFIG_KASAN 활성화 여부."""
        return self._symbols.is_config_enabled("CONFIG_KASAN")

    @property
    def is_sw_tags(self) -> bool:
        """CONFIG_KASAN_SW_TAGS 활성화 여부."""
        return self._symbols.is_config_enabled("CONFIG_KASAN_SW_TAGS")

    @property
    def shadow_offset(self) -> int:
        """kasan_shadow_offset 값."""
        if self._shadow_offset is None:
            addr = self._symbols.to_addr("kasan_shadow_offset")
            if addr is not None:
                self._shadow_offset = self._backend.read_u64(addr)
            else:
                raise ValueError("kasan_shadow_offset symbol not found")
        return self._shadow_offset

    @property
    def stack_depot(self) -> StackDepotResolver | None:
        """Stack depot resolver (lazy init)."""
        if self._stack_depot is None and self._symbols.is_symbol_valid(
            "stack_depot_pools"
        ):
            from di_memory.core.stackdepot import StackDepotResolver

            self._stack_depot = StackDepotResolver(
                self._backend, self._structs, self._symbols
            )
        return self._stack_depot

    # =========================================================================
    # Pointer Tag 조작
    # =========================================================================

    def get_tag(self, ptr: int) -> int:
        """포인터에서 태그 추출 (상위 1바이트).

        Args:
            ptr: 태그된 포인터

        Returns:
            8비트 태그 값 (0x00-0xFF)
        """
        return (ptr >> self.TAG_SHIFT) & 0xFF

    def set_tag(self, ptr: int, tag: int) -> int:
        """포인터에 태그 설정.

        Args:
            ptr: 원본 포인터
            tag: 설정할 태그 (0x00-0xFF)

        Returns:
            태그가 설정된 포인터
        """
        untagged = ptr & ~self.TAG_MASK
        return untagged | ((tag & 0xFF) << self.TAG_SHIFT)

    def reset_tag(self, ptr: int) -> int:
        """태그 제거하고 커널 주소로 복원.

        AArch64 커널 주소는 상위 비트가 1로 채워져야 함.
        TBI로 인해 무시되는 상위 바이트를 0xFF로 설정.

        Args:
            ptr: 태그된 포인터

        Returns:
            태그가 제거된 커널 주소
        """
        return ptr | self.TAG_MASK

    # =========================================================================
    # Shadow Memory 접근
    # =========================================================================

    def mem_to_shadow(self, addr: int) -> int:
        """메모리 주소를 shadow 주소로 변환.

        Args:
            addr: 메모리 주소 (tagged or untagged)

        Returns:
            Shadow 메모리 주소
        """
        untagged = self.reset_tag(addr)
        return (untagged >> self.SHADOW_SCALE_SHIFT) + self.shadow_offset

    def shadow_to_mem(self, shadow_addr: int) -> int:
        """Shadow 주소를 메모리 주소로 변환.

        Args:
            shadow_addr: Shadow 메모리 주소

        Returns:
            원본 메모리 주소 (untagged)
        """
        return (shadow_addr - self.shadow_offset) << self.SHADOW_SCALE_SHIFT

    def get_mem_tag(self, addr: int) -> int:
        """메모리 태그 조회.

        Shadow memory에서 해당 주소의 태그 값을 읽음.

        Args:
            addr: 메모리 주소

        Returns:
            메모리 태그 (0x00-0xFF)
        """
        shadow_addr = self.mem_to_shadow(addr)
        return self._backend.read_u8(shadow_addr)

    def get_mem_tags(self, addr: int, size: int) -> list[int]:
        """범위의 메모리 태그들 조회.

        Args:
            addr: 시작 주소
            size: 크기 (bytes)

        Returns:
            각 granule의 태그 리스트
        """
        tags = []
        start = self.round_down(self.reset_tag(addr))
        end = self.round_up(self.reset_tag(addr) + size)

        for granule_addr in range(start, end, self.GRANULE_SIZE):
            tags.append(self.get_mem_tag(granule_addr))
        return tags

    # =========================================================================
    # Tag 검증
    # =========================================================================

    def tags_match(self, ptr_tag: int, mem_tag: int) -> bool:
        """태그 일치 여부 확인.

        TAG_KERNEL(0xFF)은 match-all 태그로, 모든 태그와 일치.

        Args:
            ptr_tag: 포인터 태그
            mem_tag: 메모리 태그

        Returns:
            태그 일치 여부
        """
        if ptr_tag == self.TAG_KERNEL or mem_tag == self.TAG_KERNEL:
            return True
        return ptr_tag == mem_tag

    def is_valid_tag(self, tag: int) -> bool:
        """유효한 태그 범위인지 확인.

        Args:
            tag: 태그 값

        Returns:
            유효 여부 (0x00-0xFD)
        """
        return self.TAG_MIN <= tag <= self.TAG_MAX

    def is_match_all(self, tag: int) -> bool:
        """Match-all 태그인지 확인.

        Args:
            tag: 태그 값

        Returns:
            Match-all 여부 (0xFF)
        """
        return tag == self.TAG_KERNEL

    def check_access(self, ptr: int, size: int) -> dict:
        """메모리 접근 유효성 검사.

        포인터 태그와 접근 범위 내 모든 granule의 메모리 태그를 비교.

        Args:
            ptr: 태그된 포인터
            size: 접근 크기 (bytes)

        Returns:
            dict: {
                valid: bool - 접근 유효 여부,
                ptr_tag: int - 포인터 태그,
                granules: list[dict] - 각 granule 정보,
                first_mismatch: int | None - 첫 불일치 주소
            }
        """
        ptr_tag = self.get_tag(ptr)
        untagged = self.reset_tag(ptr)

        start = self.round_down(untagged)
        end = self.round_up(untagged + size)

        granules = []
        first_mismatch = None

        for granule_addr in range(start, end, self.GRANULE_SIZE):
            mem_tag = self.get_mem_tag(granule_addr)
            match = self.tags_match(ptr_tag, mem_tag)
            granules.append(
                {
                    "addr": granule_addr,
                    "mem_tag": mem_tag,
                    "match": match,
                }
            )

            if not match and first_mismatch is None:
                first_mismatch = granule_addr

        return {
            "valid": first_mismatch is None,
            "ptr_tag": ptr_tag,
            "granules": granules,
            "first_mismatch": first_mismatch,
        }

    # =========================================================================
    # Granule 분석
    # =========================================================================

    def round_down(self, addr: int) -> int:
        """주소를 granule 경계로 내림.

        Args:
            addr: 메모리 주소

        Returns:
            16바이트 정렬된 주소
        """
        return addr & ~self.GRANULE_MASK

    def round_up(self, addr: int) -> int:
        """주소를 granule 경계로 올림.

        Args:
            addr: 메모리 주소

        Returns:
            16바이트 정렬된 주소 (올림)
        """
        return (addr + self.GRANULE_MASK) & ~self.GRANULE_MASK

    def iter_granules(self, start: int, size: int) -> Iterator[tuple[int, int]]:
        """Granule 순회.

        Args:
            start: 시작 주소
            size: 크기 (bytes)

        Yields:
            (granule_addr, mem_tag) 튜플
        """
        untagged = self.reset_tag(start)
        aligned_start = self.round_down(untagged)
        aligned_end = self.round_up(untagged + size)

        for addr in range(aligned_start, aligned_end, self.GRANULE_SIZE):
            yield addr, self.get_mem_tag(addr)

    # =========================================================================
    # 메모리 상태 분석
    # =========================================================================

    def get_memory_state(self, addr: int) -> dict:
        """주소의 메모리 상태 조회.

        Args:
            addr: 메모리 주소 (tagged or untagged)

        Returns:
            dict: {
                addr: int - 원본 주소,
                untagged_addr: int - 태그 제거된 주소,
                shadow_addr: int - shadow 주소,
                ptr_tag: int - 포인터 태그,
                mem_tag: int - 메모리 태그,
                match: bool - 태그 일치 여부,
                state: str - 상태 설명
            }
        """
        ptr_tag = self.get_tag(addr)
        untagged = self.reset_tag(addr)
        shadow_addr = self.mem_to_shadow(untagged)
        mem_tag = self.get_mem_tag(untagged)
        match = self.tags_match(ptr_tag, mem_tag)

        if mem_tag == self.TAG_INVALID:
            state = "freed/invalid"
        elif mem_tag == self.TAG_KERNEL:
            state = "kernel (untagged)"
        elif match:
            state = "accessible"
        else:
            state = "tag mismatch"

        return {
            "addr": addr,
            "untagged_addr": untagged,
            "shadow_addr": shadow_addr,
            "ptr_tag": ptr_tag,
            "mem_tag": mem_tag,
            "match": match,
            "state": state,
        }

    def analyze_region(self, start: int, size: int) -> dict:
        """메모리 영역의 태그 분석.

        Args:
            start: 시작 주소
            size: 크기 (bytes)

        Returns:
            dict: {
                start: int,
                size: int,
                granule_count: int,
                tags: list[dict] - 각 granule 정보,
                unique_tags: set[int],
                transitions: list[dict] - 태그 변경 지점
            }
        """
        untagged = self.reset_tag(start)
        aligned_start = self.round_down(untagged)
        aligned_end = self.round_up(untagged + size)

        tags = []
        unique_tags = set()
        transitions = []
        prev_tag = None

        for addr in range(aligned_start, aligned_end, self.GRANULE_SIZE):
            mem_tag = self.get_mem_tag(addr)
            tags.append({"addr": addr, "tag": mem_tag})
            unique_tags.add(mem_tag)

            if prev_tag is not None and prev_tag != mem_tag:
                transitions.append(
                    {
                        "addr": addr,
                        "from_tag": prev_tag,
                        "to_tag": mem_tag,
                    }
                )
            prev_tag = mem_tag

        return {
            "start": aligned_start,
            "size": aligned_end - aligned_start,
            "granule_count": len(tags),
            "tags": tags,
            "unique_tags": unique_tags,
            "transitions": transitions,
        }

    def find_object_bounds(self, addr: int) -> tuple[int, int] | None:
        """동일 태그로 object 경계 추정.

        주어진 주소에서 시작하여 동일 태그를 가진 연속 영역을 찾음.

        Args:
            addr: 검색 시작 주소

        Returns:
            (start, end) 튜플 또는 None
        """
        untagged = self.reset_tag(addr)
        aligned = self.round_down(untagged)
        target_tag = self.get_mem_tag(aligned)

        if target_tag == self.TAG_INVALID or target_tag == self.TAG_KERNEL:
            return None

        # 앞으로 검색
        start = aligned
        search_addr = aligned - self.GRANULE_SIZE
        max_search = 4096  # 최대 검색 범위
        searched = 0

        while searched < max_search:
            try:
                tag = self.get_mem_tag(search_addr)
                if tag != target_tag:
                    break
                start = search_addr
                search_addr -= self.GRANULE_SIZE
                searched += self.GRANULE_SIZE
            except (ValueError, OSError):
                break

        # 뒤로 검색
        end = aligned + self.GRANULE_SIZE
        search_addr = aligned + self.GRANULE_SIZE
        searched = 0

        while searched < max_search:
            try:
                tag = self.get_mem_tag(search_addr)
                if tag != target_tag:
                    break
                end = search_addr + self.GRANULE_SIZE
                search_addr += self.GRANULE_SIZE
                searched += self.GRANULE_SIZE
            except (ValueError, OSError):
                break

        return start, end

    # =========================================================================
    # SLUB 연동
    # =========================================================================

    def get_alloc_meta(
        self, cache: ctypes.Structure, obj_addr: int
    ) -> ctypes.Structure | None:
        """Object의 kasan_alloc_meta 구조체 조회.

        Args:
            cache: struct kmem_cache
            obj_addr: Object 주소

        Returns:
            struct kasan_alloc_meta 또는 None
        """
        if not self._structs.has_member("struct kmem_cache", "kasan_info"):
            return None

        if not self._structs.has_member("struct kasan_cache", "alloc_meta_offset"):
            return None

        kasan_info_offset = self._structs.offsetof("struct kmem_cache", "kasan_info")
        cache_addr = cache._base if hasattr(cache, "_base") else 0

        # kasan_info.alloc_meta_offset
        alloc_meta_offset_addr = (
            cache_addr
            + kasan_info_offset
            + self._structs.offsetof("struct kasan_cache", "alloc_meta_offset")
        )
        alloc_meta_offset = self._backend.read_u32(alloc_meta_offset_addr)

        if alloc_meta_offset == 0:
            return None

        meta_addr = self.reset_tag(obj_addr) + alloc_meta_offset
        return self._structs.read(meta_addr, "struct kasan_alloc_meta")

    def get_alloc_track(self, cache: ctypes.Structure, obj_addr: int) -> dict | None:
        """Object의 alloc track 정보 조회.

        Args:
            cache: struct kmem_cache
            obj_addr: Object 주소

        Returns:
            dict: {pid, stack: [symbols]} 또는 None
        """
        meta = self.get_alloc_meta(cache, obj_addr)
        if meta is None:
            return None

        return self._parse_track(meta.alloc_track)

    def get_free_track(self, cache: ctypes.Structure, obj_addr: int) -> dict | None:
        """Object의 free track 정보 조회.

        Args:
            cache: struct kmem_cache
            obj_addr: Object 주소

        Returns:
            dict: {pid, stack: [symbols]} 또는 None
        """
        meta = self.get_alloc_meta(cache, obj_addr)
        if meta is None:
            return None

        return self._parse_track(meta.free_track)

    def _parse_track(self, track: ctypes.Structure) -> dict | None:
        """kasan_track 구조체 파싱.

        Args:
            track: struct kasan_track

        Returns:
            dict: {pid, stack: [symbols]}
        """
        pid = track.pid
        stack_handle = track.stack

        if stack_handle == 0:
            return {"pid": pid, "stack": []}

        stack = self._resolve_stack(stack_handle)
        return {"pid": pid, "stack": stack}

    def _resolve_stack(self, handle: int) -> list[str]:
        """Stack depot handle을 심볼로 resolve.

        Args:
            handle: depot_stack_handle_t

        Returns:
            심볼 문자열 리스트
        """
        if handle == 0 or self.stack_depot is None:
            return []

        addrs = self.stack_depot.get_stack_addrs(handle)
        return self._symbols.resolve_stack(addrs)

    # =========================================================================
    # Corruption 탐지
    # =========================================================================

    def detect_tag_mismatch(self, ptr: int, size: int) -> dict | None:
        """태그 불일치 탐지.

        Args:
            ptr: 태그된 포인터
            size: 접근 크기

        Returns:
            dict: {ptr, ptr_tag, mismatches: [...]} 또는 None (불일치 없음)
        """
        result = self.check_access(ptr, size)
        if result["valid"]:
            return None

        mismatches = [
            {"addr": g["addr"], "mem_tag": g["mem_tag"]}
            for g in result["granules"]
            if not g["match"]
        ]

        return {
            "ptr": ptr,
            "ptr_tag": result["ptr_tag"],
            "mismatches": mismatches,
        }

    def classify_bug_type(self, mem_tag: int) -> str:
        """버그 유형 분류.

        Args:
            mem_tag: 메모리 태그

        Returns:
            버그 유형 문자열
        """
        if mem_tag == self.TAG_INVALID:
            return KASAN_BUG_USE_AFTER_FREE
        elif mem_tag == self.TAG_KERNEL:
            # Untagged 메모리에 tagged 접근
            return KASAN_BUG_OUT_OF_BOUNDS
        else:
            return KASAN_BUG_TAG_MISMATCH

    # =========================================================================
    # 출력/포맷팅
    # =========================================================================

    def format_ptr(self, ptr: int) -> str:
        """Tagged pointer 포맷.

        Args:
            ptr: 태그된 포인터

        Returns:
            "[tag]address" 형식 문자열
        """
        tag = self.get_tag(ptr)
        untagged = self.reset_tag(ptr)
        return f"[{tag:02x}]{untagged:016x}"

    def dump_tags(self, start: int, size: int, granules_per_line: int = 16) -> str:
        """영역 태그 덤프.

        Args:
            start: 시작 주소
            size: 크기
            granules_per_line: 줄당 granule 수

        Returns:
            태그 덤프 문자열
        """
        lines = []
        untagged = self.reset_tag(start)
        aligned_start = self.round_down(untagged)
        aligned_end = self.round_up(untagged + size)

        addr = aligned_start
        while addr < aligned_end:
            line_tags = []
            line_start = addr

            for _ in range(granules_per_line):
                if addr >= aligned_end:
                    break
                tag = self.get_mem_tag(addr)
                line_tags.append(f"[{tag:02x}]")
                addr += self.GRANULE_SIZE

            lines.append(f"0x{line_start:016x}: {''.join(line_tags)}")

        return "\n".join(lines)
