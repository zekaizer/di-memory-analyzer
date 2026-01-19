"""Corruption 모듈 공통 헬퍼 함수."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from di_memory.analyzers.kasan import KasanAnalyzer


def check_object_state_consistency(
    is_in_freelist: bool,
    mem_tag: int,
    kasan: KasanAnalyzer,
) -> tuple[bool, str | None]:
    """
    Object 상태 일관성 검사.

    SLUB freelist 상태와 KASAN 태그가 일치하는지 검사.

    Args:
        is_in_freelist: freelist에 있는지 (free 상태)
        mem_tag: KASAN 메모리 태그
        kasan: KasanAnalyzer 인스턴스 (TAG_INVALID 참조용)

    Returns:
        (is_consistent, error_type): 일관성 여부와 에러 유형
        - (True, None): 일관적
        - (False, "freed_but_valid_tag"): freelist에 있는데 valid 태그
        - (False, "allocated_but_invalid_tag"): freelist에 없는데 invalid 태그
    """
    is_invalid_tag = mem_tag == kasan.TAG_INVALID

    if is_in_freelist and not is_invalid_tag:
        return False, "freed_but_valid_tag"
    if not is_in_freelist and is_invalid_tag:
        return False, "allocated_but_invalid_tag"

    return True, None


def format_state_error(
    error_type: str,
    object_addr: int,
    object_index: int,
    mem_tag: int,
) -> dict:
    """
    상태 불일치 에러 포맷.

    Args:
        error_type: 에러 유형
        object_addr: object 주소
        object_index: object 인덱스
        mem_tag: 메모리 태그

    Returns:
        에러 정보 dict
    """
    if error_type == "freed_but_valid_tag":
        details = f"Object in freelist but tag 0x{mem_tag:02x} != 0xFE"
    elif error_type == "allocated_but_invalid_tag":
        details = "Object allocated but has TAG_INVALID"
    else:
        details = f"Unknown error: {error_type}"

    return {
        "type": error_type,
        "object_addr": object_addr,
        "object_index": object_index,
        "mem_tag": mem_tag,
        "details": details,
    }
