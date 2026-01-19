# CLAUDE.md - DI Memory Analysis Module

## 프로젝트 개요

DI Notebook 환경에서 Linux 커널 RAMDUMP를 분석하기 위한 메모리 분석 모듈.
Page, SLUB, KASAN, Folio 서브시스템 분석 및 메모리 corruption 탐지 기능 제공.

## 기술 스택

- Python 3.10+
- uv (프로젝트/패키지 매니저)
- ruff (linter/formatter)
- ctypes (커널 구조체 접근)
- DINotebookWrapper (DI 환경 인터페이스)

## 설계 원칙

| 원칙 | 설명 |
|------|------|
| Backend 추상화 | `DIBackend` Protocol로 DI 의존성 격리, Mock 테스트 가능 |
| ctypes.Structure 직접 반환 | 커널 구조체를 래핑하지 않고 ctypes 그대로 반환 |
| 최소 추상화 | 해석/분석 필요한 경우만 dict/list 반환 |
| Lazy Evaluation | 대량 순회 시 Iterator/Generator 사용 |

## 디렉토리 구조

```
src/di_memory/
├── __init__.py              # MemoryAnalyzer (진입점)
├── backend/
│   ├── protocol.py          # DIBackend Protocol 정의
│   ├── real.py              # Production 구현 (DINotebookWrapper 래핑)
│   └── mock.py              # Testing 구현
├── core/
│   ├── struct_helper.py     # 구조체 메타정보, read, container_of
│   ├── address_translator.py # VA/PA/PFN 변환
│   └── symbol_resolver.py   # 심볼 조회, 스택 resolve
├── analyzers/
│   ├── base.py              # BaseAnalyzer
│   ├── page.py              # PageAnalyzer
│   ├── slub.py              # SlubAnalyzer (+Tracking)
│   ├── kasan.py             # KasanAnalyzer
│   └── folio.py             # FolioAnalyzer
├── corruption/
│   ├── detector.py          # CorruptionDetector (통합)
│   ├── bitflip.py           # 1-bit flip 탐지
│   ├── freelist.py          # Freelist corruption
│   ├── uaf.py               # Use-after-free
│   └── oob.py               # Out-of-bounds
└── utils/
    ├── flags.py             # Page/Slab 플래그 정의
    └── constants.py         # 커널 상수
```

## 모듈 의존성

```
MemoryAnalyzer
    │
    ├──► backend/protocol.py (DIBackend)
    │         ▲
    │         └── backend/real.py, backend/mock.py
    │
    ├──► core/* (Backend에만 의존)
    │         ▲
    ├──► analyzers/* (Core에 의존)
    │         ▲
    └──► corruption/* (Analyzers + Core에 의존)

utils/* ← 모든 모듈에서 import 가능 (의존성 없음)
```

## 반환 타입 규칙

| 유형 | 반환 타입 | 예시 |
|------|----------|------|
| 커널 구조체 조회 | `ctypes.Structure` | `get_cache()`, `get_page()` |
| 구조체 순회 | `Iterator[ctypes.Structure]` | `iter_caches()` |
| 주소 목록 | `Iterator[int]` | `iter_objects()` |
| 복합 조회 결과 | `tuple` | `find_owning_cache()` |
| 플래그 해석 | `list[str]` | `decode_flags()` |
| 통계/분석 | `dict` | `get_cache_stats()` |
| Corruption 진단 | `dict` | `CorruptionDetector.*` |
| 단순 상태 | `bool`, `int` | `is_free()`, `sizeof()` |

## 코딩 컨벤션

### 네이밍

```python
# 클래스: PascalCase
class SlubAnalyzer:

# 메서드/함수: snake_case
def get_cache(self, name: str):
def iter_objects(self, slab):

# 상수: UPPER_SNAKE_CASE
PAGE_SIZE = 4096
PG_slab = 1 << 7

# Private: underscore prefix
self._backend
self._cache: dict[str, int] = {}
def _read_struct(self, addr, name):
```

### 타입 힌트

- 모든 public 메서드에 타입 힌트 필수

### Docstring

```python
def find_owning_cache(self, addr: int) -> tuple | None:
    """
    주소가 속한 slab cache 찾기.

    Args:
        addr: 검색할 메모리 주소

    Returns:
        (cache, slab, obj_addr, obj_index) tuple 또는 None
        - cache: struct kmem_cache
        - slab: struct slab
        - obj_addr: object 시작 주소
        - obj_index: slab 내 object 인덱스
    """
```

### Error Handling

```python
# 찾지 못한 경우: None 반환 (예외 아님)
def get_cache(self, name: str) -> ctypes.Structure | None:
    ...
    return None  # not found

# 잘못된 인자: ValueError
def get_page(self, pfn: int) -> ctypes.Structure:
    if pfn < 0:
        raise ValueError(f"Invalid PFN: {pfn}")

# Backend 오류: 그대로 전파 (래핑하지 않음)
```

## 핵심 인터페이스

### DIBackend Protocol

```python
class DIBackend(Protocol):
    # Structure 메타정보
    def sizeof(self, struct_name: str) -> int: ...
    def offsetof(self, struct_name: str, member: str) -> int: ...
    def has_member(self, struct_name: str, member: str) -> bool: ...

    # Memory 읽기 (addr: int | str - 주소 또는 심볼 이름)
    def read_type(self, addr: int | str, type_name: str | None = None) -> ctypes.Structure | int: ...
    def read_u8(self, addr: int | str) -> int: ...
    def read_u16(self, addr: int | str) -> int: ...
    def read_u32(self, addr: int | str) -> int: ...
    def read_u64(self, addr: int | str) -> int: ...
    def read_bytes(self, addr: int | str, size: int) -> bytes: ...
    def read_pointer(self, addr: int | str) -> int: ...
    def read_string(self, addr: int | str, max_len: int = 256) -> str: ...

    # Symbol
    def symbol_to_addr(self, name: str) -> int | None: ...
    def addr_to_symbol(self, addr: int) -> tuple[str, int] | None: ...  # (심볼, 오프셋)
    def is_symbol_valid(self, name: str) -> bool: ...

    # Kernel Config
    def is_config_enabled(self, config_name: str) -> bool | int | str | None: ...

    # 주소 변환
    def virt_to_phys(self, vaddr: int) -> int | None: ...
    def phys_to_virt(self, paddr: int) -> int: ...

    # Per-CPU
    def per_cpu(self, symbol: str, cpu_id: int) -> int: ...

    # Container
    def container_of(self, addr: int, struct_name: str, member: str) -> int: ...
```

### MemoryAnalyzer 초기화

```python
# Production
ma = MemoryAnalyzer(di=DINotebookWrapper())

# Testing
ma = MemoryAnalyzer(backend=DIBackendMock())
```

## 구현 우선순위

1. **backend/** - DIBackend Protocol, Real/Mock 구현
2. **core/** - StructHelper, AddressTranslator, SymbolResolver
3. **analyzers/slub.py** - Crash 분석 핵심
4. **analyzers/page.py** - Slub과 연계 필수
5. **analyzers/slub.py (Tracking)** - UAF/Leak 분석
6. **analyzers/kasan.py** - Corruption 검증 보조
7. **corruption/** - Cross-module 분석
8. **analyzers/folio.py** - 필요 시 확장

## 테스트

### 테스트 구조

```
tests/
├── conftest.py          # pytest fixtures (mock backend)
├── unit/                # Mock 기반 단위 테스트
│   ├── core/
│   ├── analyzers/
│   └── corruption/
└── integration/         # Fixture 기반 통합 테스트
```

### Mock 사용 예시

```python
# tests/conftest.py
@pytest.fixture
def mock_backend():
    backend = DIBackendMock()
    backend.register_struct("struct kmem_cache", 256, {
        "name": 0,
        "object_size": 8,
    })
    backend.register_symbol("slab_caches", 0xffff888100000000)
    return backend

@pytest.fixture
def slub_analyzer(mock_backend):
    structs = StructHelper(mock_backend)
    addr = AddressTranslator(mock_backend, structs)
    symbols = SymbolResolver(mock_backend)
    return SlubAnalyzer(mock_backend, structs, addr, symbols)
```

### 테스트 실행

```bash
# 전체 테스트
uv run pytest

# 특정 모듈
uv run pytest tests/unit/analyzers/test_slub.py

# Coverage
uv run pytest --cov=di_memory
```

### Linting & Formatting

```bash
# Lint 검사
uv run ruff check .

# Lint 자동 수정
uv run ruff check --fix .

# Format 검사
uv run ruff format --check .

# Format 적용
uv run ruff format .
```

## 커밋 메시지 규칙

```
<type>(<scope>): <subject>

type: feat, fix, refactor, test, docs, chore
scope: backend, core, slub, page, kasan, folio, corruption
```

예시:
```
feat(slub): add object tracking API
fix(core): handle invalid PFN in address translation
test(corruption): add bitflip detection tests
docs: update CLAUDE.md with testing section
```

## 참고 자료

- Linux Kernel Source: mm/slub.c, mm/page_alloc.c, mm/kasan/
- Documentation/mm/slub.rst
- include/linux/mm_types.h (struct page, struct folio)
- include/linux/slub_def.h (struct kmem_cache)
