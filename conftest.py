"""
Pytest configuration for making the project importable as:
    import classifier, adaptive_module, ...

By default, depending on how pytest is invoked, the project root may not be
on sys.path, which breaks imports like `from adaptive_module.core import APPADCore`.
This file ensures that the repository root is always on sys.path.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
root_str = str(ROOT)

if root_str not in sys.path:
    # Put project root at the beginning so it has priority over site-packages
    sys.path.insert(0, root_str)

