"""pytest configuration: put `tests/` and `tools/` on sys.path so test modules
can import `harness` and the tool modules directly.

We deliberately avoid making `tests/` a Python package — the directory only
contains test modules and the harness, and the simpler import path keeps
fixture wiring obvious.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
TOOLS_DIR = REPO_ROOT / "tools"

for entry in (TESTS_DIR, TOOLS_DIR):
    s = str(entry)
    if s not in sys.path:
        sys.path.insert(0, s)
