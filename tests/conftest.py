"""pytest configuration: put `tests/` and `tools/` on sys.path so test modules
can import `harness` and the tool modules directly.

We deliberately avoid making `tests/` a Python package — the directory only
contains test modules and the harness, and the simpler import path keeps
fixture wiring obvious.

Hardware-target opt-in. Tests in `tests/hardware/` exercise a physical
Adafruit ESP32-C6 Feather connected over USB-C (per ADR-0010 the
USB-Serial/JTAG endpoint enumerates as /dev/cu.usbmodemNNNN). They are
slow and require the chip to be on bench, so we mark them with the
`hardware` pytest marker and skip them unless `--hardware` is passed
(or `RATSPEAK_HW=1` is set in the environment for CI parity).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
TOOLS_DIR = REPO_ROOT / "tools"

for entry in (TESTS_DIR, TOOLS_DIR):
    s = str(entry)
    if s not in sys.path:
        sys.path.insert(0, s)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--hardware",
        action="store_true",
        default=False,
        help="Run tests marked @pytest.mark.hardware against the physical "
             "Adafruit ESP32-C6 Feather (default: skipped).",
    )
    parser.addoption(
        "--hardware-port",
        action="store",
        default=os.environ.get("RATSPEAK_HW_PORT", "/dev/cu.usbmodem4101"),
        help="Serial port for the C6 (default: /dev/cu.usbmodem4101 or "
             "$RATSPEAK_HW_PORT). Only consulted when --hardware is set.",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "hardware: requires the Adafruit ESP32-C6 Feather connected over "
        "USB-C (run with --hardware or set RATSPEAK_HW=1)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    enabled = config.getoption("--hardware") or os.environ.get("RATSPEAK_HW") == "1"
    if enabled:
        return
    skip_hw = pytest.mark.skip(reason="needs --hardware (physical C6 on bench)")
    for item in items:
        if "hardware" in item.keywords:
            item.add_marker(skip_hw)
