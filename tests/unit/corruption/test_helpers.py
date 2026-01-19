"""Corruption helpers 테스트."""

from __future__ import annotations

import pytest

from tests.conftest import MockDIBackend


@pytest.fixture
def kasan_analyzer(kasan_mock_backend: MockDIBackend):
    """KasanAnalyzer fixture."""
    from di_memory.analyzers.kasan import KasanAnalyzer
    from di_memory.core.address_translator import AddressTranslator
    from di_memory.core.kernel_resolver import KernelResolver
    from di_memory.core.struct_helper import StructHelper

    structs = StructHelper(kasan_mock_backend)
    addr = AddressTranslator(kasan_mock_backend)
    symbols = KernelResolver(kasan_mock_backend)

    return KasanAnalyzer(
        backend=kasan_mock_backend,
        structs=structs,
        addr=addr,
        symbols=symbols,
    )


class TestCheckObjectStateConsistency:
    """check_object_state_consistency() 테스트."""

    def test_consistent_allocated(self, kasan_analyzer):
        """Allocated 상태 일관성."""
        from di_memory.corruption.helpers import check_object_state_consistency

        # freelist에 없고 valid 태그 -> 일관적
        is_consistent, error_type = check_object_state_consistency(
            is_in_freelist=False,
            mem_tag=0x42,  # valid tag
            kasan=kasan_analyzer,
        )

        assert is_consistent is True
        assert error_type is None

    def test_consistent_freed(self, kasan_analyzer):
        """Freed 상태 일관성."""
        from di_memory.corruption.helpers import check_object_state_consistency

        # freelist에 있고 invalid 태그 -> 일관적
        is_consistent, error_type = check_object_state_consistency(
            is_in_freelist=True,
            mem_tag=kasan_analyzer.TAG_INVALID,
            kasan=kasan_analyzer,
        )

        assert is_consistent is True
        assert error_type is None

    def test_inconsistent_freed_but_valid_tag(self, kasan_analyzer):
        """Freelist에 있는데 valid 태그."""
        from di_memory.corruption.helpers import check_object_state_consistency

        # freelist에 있는데 valid 태그 -> 불일치
        is_consistent, error_type = check_object_state_consistency(
            is_in_freelist=True,
            mem_tag=0x42,  # valid tag, should be invalid
            kasan=kasan_analyzer,
        )

        assert is_consistent is False
        assert error_type == "freed_but_valid_tag"

    def test_inconsistent_allocated_but_invalid_tag(self, kasan_analyzer):
        """Freelist에 없는데 invalid 태그."""
        from di_memory.corruption.helpers import check_object_state_consistency

        # freelist에 없는데 invalid 태그 -> 불일치
        is_consistent, error_type = check_object_state_consistency(
            is_in_freelist=False,
            mem_tag=kasan_analyzer.TAG_INVALID,
            kasan=kasan_analyzer,
        )

        assert is_consistent is False
        assert error_type == "allocated_but_invalid_tag"


class TestFormatStateError:
    """format_state_error() 테스트."""

    def test_format_freed_but_valid_tag(self):
        """freed_but_valid_tag 에러 포맷."""
        from di_memory.corruption.helpers import format_state_error

        result = format_state_error(
            error_type="freed_but_valid_tag",
            object_addr=0xFFFF_8880_1000_0000,
            object_index=3,
            mem_tag=0x42,
        )

        assert result["type"] == "freed_but_valid_tag"
        assert result["object_addr"] == 0xFFFF_8880_1000_0000
        assert result["object_index"] == 3
        assert result["mem_tag"] == 0x42
        assert "0x42" in result["details"]
        assert "0xFE" in result["details"]

    def test_format_allocated_but_invalid_tag(self):
        """allocated_but_invalid_tag 에러 포맷."""
        from di_memory.corruption.helpers import format_state_error

        result = format_state_error(
            error_type="allocated_but_invalid_tag",
            object_addr=0xFFFF_8880_1000_0100,
            object_index=5,
            mem_tag=0xFE,
        )

        assert result["type"] == "allocated_but_invalid_tag"
        assert result["object_addr"] == 0xFFFF_8880_1000_0100
        assert result["object_index"] == 5
        assert "TAG_INVALID" in result["details"]

    def test_format_unknown_error(self):
        """Unknown 에러 포맷."""
        from di_memory.corruption.helpers import format_state_error

        result = format_state_error(
            error_type="custom_error",
            object_addr=0xFFFF_8880_2000_0000,
            object_index=0,
            mem_tag=0x00,
        )

        assert result["type"] == "custom_error"
        assert "Unknown error" in result["details"]
