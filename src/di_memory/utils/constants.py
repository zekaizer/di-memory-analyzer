"""커널 상수 정의.

Config 의존 값은 런타임 조회. 이 모듈은 enum 이름만 정의.
"""

# =============================================================================
# Enum 이름
# =============================================================================

PAGEFLAGS_ENUM = "pageflags"
ZONE_TYPE_ENUM = "zone_type"
MIGRATE_TYPE_ENUM = "migratetype"

# =============================================================================
# Zone 멤버 이름
# =============================================================================

ZONE_DMA = "ZONE_DMA"
ZONE_DMA32 = "ZONE_DMA32"
ZONE_NORMAL = "ZONE_NORMAL"
ZONE_MOVABLE = "ZONE_MOVABLE"

# =============================================================================
# Migrate 멤버 이름
# =============================================================================

MIGRATE_UNMOVABLE = "MIGRATE_UNMOVABLE"
MIGRATE_MOVABLE = "MIGRATE_MOVABLE"
MIGRATE_RECLAIMABLE = "MIGRATE_RECLAIMABLE"

# =============================================================================
# KASAN SW_TAGS Constants (AArch64 TBI, Linux 6.12+)
# =============================================================================

# Tag configuration (AArch64 TBI - Top Byte Ignore)
KASAN_TAG_SHIFT = 56
KASAN_TAG_MASK = 0xFF << KASAN_TAG_SHIFT

# Shadow scale (SW_TAGS: 16:1 ratio)
KASAN_SHADOW_SCALE_SHIFT = 4
KASAN_GRANULE_SIZE = 1 << KASAN_SHADOW_SCALE_SHIFT  # 16 bytes
KASAN_GRANULE_MASK = KASAN_GRANULE_SIZE - 1

# -----------------------------------------------------------------------------
# Tag values
# -----------------------------------------------------------------------------
KASAN_TAG_MIN = 0x00  # Minimum valid tag
KASAN_TAG_MAX = 0xFD  # Maximum valid tag
KASAN_TAG_INVALID = 0xFE  # Invalid (freed, redzone)
KASAN_TAG_KERNEL = 0xFF  # Untagged / match-all

# -----------------------------------------------------------------------------
# Bug types
# -----------------------------------------------------------------------------
KASAN_BUG_TAG_MISMATCH = "tag-mismatch"
KASAN_BUG_USE_AFTER_FREE = "use-after-free"
KASAN_BUG_OUT_OF_BOUNDS = "out-of-bounds"
