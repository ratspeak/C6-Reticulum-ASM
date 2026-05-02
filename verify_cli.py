#!/usr/bin/env python3
"""Repo-root entrypoint that forwards to tests/harness/verify.py.

The shell wrapper `./verify` execs this so users get a uniform command from
the repo root regardless of platform conventions for shell scripts.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from harness import verify  # noqa: E402

if __name__ == "__main__":
    sys.exit(verify.main(sys.argv[1:]))
