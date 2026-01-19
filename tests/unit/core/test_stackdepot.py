"""StackDepotResolver 테스트."""

from __future__ import annotations

import pytest

from di_memory.core.stackdepot import StackDepotResolver
from tests.conftest import MockDIBackend


@pytest.fixture
def stack_depot_resolver(mock_backend: MockDIBackend, kernel_resolver):
    """StackDepotResolver 인스턴스."""
    # stack_pools 심볼 등록
    mock_backend._symbols["stack_pools"] = 0xFFFF_FFFF_8300_0000
    return StackDepotResolver(mock_backend, kernel_resolver)


@pytest.fixture
def setup_stack_depot(mock_backend: MockDIBackend):
    """Stack depot 데이터 설정."""
    # stack_pools 심볼 및 pool 설정
    stack_pools_addr = 0xFFFF_FFFF_8300_0000
    mock_backend._symbols["stack_pools"] = stack_pools_addr

    # pool[0] 포인터 설정
    pool_0_addr = 0xFFFF_8880_5000_0000
    mock_backend._memory[stack_pools_addr] = pool_0_addr.to_bytes(8, "little")

    # pool[1] 포인터 설정 (NULL)
    mock_backend._memory[stack_pools_addr + 8] = (0).to_bytes(8, "little")

    # stack_record at pool_0 + offset
    # handle = (pool_index << 16) | (offset >> 4)
    # pool_index = 0, offset = 0x100 -> handle = 0x0000_0010
    record_addr = pool_0_addr + 0x100

    # struct stack_record layout:
    # hash_list (16) + hash (4) + size (4) + entries[]
    # entries offset = 24

    # size = 3 frames
    size_offset = mock_backend.offsetof("struct stack_record", "size")
    mock_backend._memory[record_addr + size_offset] = (3).to_bytes(4, "little")

    # entries (3 addresses)
    entries_offset = mock_backend.offsetof("struct stack_record", "entries")
    entries_addr = record_addr + entries_offset

    # 스택 주소들
    stack_addrs = [
        0xFFFF_FFFF_8100_1234,  # kalloc_internal+0x34
        0xFFFF_FFFF_8100_5678,  # kmem_cache_alloc+0x78
        0xFFFF_FFFF_8100_9ABC,  # do_something+0xBC
    ]

    for i, addr in enumerate(stack_addrs):
        mock_backend._memory[entries_addr + i * 8] = addr.to_bytes(8, "little")

    # 심볼 등록 (addr_to_symbol용)
    mock_backend._symbols["kalloc_internal"] = 0xFFFF_FFFF_8100_1200
    mock_backend._symbols["kmem_cache_alloc"] = 0xFFFF_FFFF_8100_5600
    mock_backend._symbols["do_something"] = 0xFFFF_FFFF_8100_9A00

    return {
        "handle": 0x0000_0010,  # pool_index=0, offset=0x100 (shifted by 4)
        "stack_addrs": stack_addrs,
        "pool_addr": pool_0_addr,
        "record_addr": record_addr,
    }


class TestStackDepotResolverBasic:
    """기본 기능 테스트."""

    def test_stack_pools_property(self, stack_depot_resolver):
        """stack_pools 속성."""
        assert stack_depot_resolver.stack_pools == 0xFFFF_FFFF_8300_0000

    def test_stack_pools_not_found(self, mock_backend, kernel_resolver):
        """stack_pools 심볼 없음."""
        # stack_pools 심볼 제거
        mock_backend._symbols.pop("stack_pools", None)
        resolver = StackDepotResolver(mock_backend, kernel_resolver)
        assert resolver.stack_pools is None

    def test_resolve_handle_zero(self, stack_depot_resolver):
        """핸들 0은 빈 스택."""
        result = stack_depot_resolver.resolve_handle(0)
        assert result == []


class TestStackDepotResolverResolve:
    """resolve 메서드 테스트."""

    def test_resolve_handle(self, mock_backend, kernel_resolver, setup_stack_depot):
        """핸들에서 스택 주소 목록 추출."""
        resolver = StackDepotResolver(mock_backend, kernel_resolver)
        data = setup_stack_depot

        result = resolver.resolve_handle(data["handle"])

        assert len(result) == 3
        assert result[0] == 0xFFFF_FFFF_8100_1234
        assert result[1] == 0xFFFF_FFFF_8100_5678
        assert result[2] == 0xFFFF_FFFF_8100_9ABC

    def test_resolve_stack(self, mock_backend, kernel_resolver, setup_stack_depot):
        """핸들에서 심볼 문자열 목록 추출."""
        resolver = StackDepotResolver(mock_backend, kernel_resolver)
        data = setup_stack_depot

        result = resolver.resolve_stack(data["handle"])

        assert len(result) == 3
        # 심볼+오프셋 형태로 변환
        assert "kalloc_internal" in result[0]
        assert "kmem_cache_alloc" in result[1]
        assert "do_something" in result[2]

    def test_resolve_handle_invalid_pool(
        self, mock_backend, kernel_resolver, setup_stack_depot
    ):
        """유효하지 않은 pool index."""
        resolver = StackDepotResolver(mock_backend, kernel_resolver)

        # pool_index = 1 (NULL pool)
        invalid_handle = 0x0001_0010
        result = resolver.resolve_handle(invalid_handle)

        assert result == []


class TestStackDepotResolverParseHandle:
    """_parse_handle 메서드 테스트."""

    def test_parse_handle(self, stack_depot_resolver):
        """핸들 파싱."""
        # handle = 0x0000_0010 -> pool_index=0, offset=0x100
        pool_index, offset, extra = stack_depot_resolver._parse_handle(0x0000_0010)
        assert pool_index == 0
        assert offset == 0x100  # 0x10 << 4

    def test_parse_handle_with_pool_index(self, stack_depot_resolver):
        """pool index가 있는 핸들."""
        # handle = 0x0001_0020 -> pool_index=1, offset=0x200
        pool_index, offset, extra = stack_depot_resolver._parse_handle(0x0001_0020)
        assert pool_index == 1
        assert offset == 0x200
