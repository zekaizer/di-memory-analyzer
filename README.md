# DI Memory Analyzer

A memory analysis module for analyzing Linux kernel RAMDUMP in DI Notebook environments.

## Features

- **Page Analyzer** - Page frame and memory zone analysis
- **SLUB Analyzer** - Slab allocator inspection with object tracking
- **KASAN Analyzer** - Kernel Address Sanitizer state analysis
- **Folio Analyzer** - Large folio and compound page analysis
- **Corruption Detector** - Memory corruption detection (bitflip, UAF, OOB, freelist)

## Requirements

- Python 3.10+
- DI Notebook environment with DINotebookWrapper

## Installation

```bash
pip install -e .
```

## Quick Start

```python
from di_memory import MemoryAnalyzer

# Initialize with DI environment
ma = MemoryAnalyzer(di=DINotebookWrapper())

# Analyze SLUB caches
for cache in ma.slub.iter_caches():
    print(cache.name, cache.object_size)

# Find which cache owns an address
result = ma.slub.find_owning_cache(0xffff888012345678)
if result:
    cache, slab, obj_addr, obj_index = result
    print(f"Object at index {obj_index} in {cache.name}")

# Detect memory corruption
report = ma.corruption.scan_cache("kmalloc-256")
```

## Project Structure

```
src/di_memory/
├── backend/      # DI environment abstraction
├── core/         # Struct helper, address translation, symbols
├── analyzers/    # Page, SLUB, KASAN, Folio analyzers
├── corruption/   # Corruption detection modules
└── utils/        # Flags and constants
```

## Testing

```bash
pytest
pytest --cov=di_memory
```

## License

Internal use only.
