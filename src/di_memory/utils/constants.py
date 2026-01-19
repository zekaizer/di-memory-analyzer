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
