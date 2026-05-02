"""Tests for src/log/log_event.S.

Static checks for the call sequence (log_hex → '\\t' → log_str → '\\r' →
'\\n'), plus an integration check via qemu — the boot.ready event _main
emits is itself a log_event call, so observing it on UART validates the
whole stack: log_hex → uart_tx_byte, log_str → uart_tx_bytes, the
literal tab and CRLF, and the tag bytes.
"""

from __future__ import annotations

import re

import pytest

from harness import build, log_parser, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# --- static --------------------------------------------------------------


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_event") > 0


def test_calls_log_hex_with_width_8(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_event")
    assert "log_hex" in body, body
    # First call to log_hex passes width=8 in a1 — the literal `8` must
    # appear as an `li a1, 8`.
    assert re.search(r"\bli\b\s+a1,\s*8\b", body), body


def test_emits_tab_and_crlf(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_event")
    # ASCII codes: TAB=9, CR=13, LF=10. Each is loaded into a0 then sent
    # via uart_tx_byte.
    for code in (9, 13, 10):
        assert re.search(rf"\bli\b\s+a0,\s*{code}\b", body), body


def test_calls_log_str_for_tag(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_event")
    assert "log_str" in body, body


# --- integration ---------------------------------------------------------


def test_boot_ready_event_round_trips_through_parser(
    artifacts: build.BuildArtifacts,
) -> None:
    """Run the firmware in qemu, parse the emitted line, assert it has
    the canonical log shape: 8-hex ts, module=boot, event=ready, no
    extra fields."""
    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    with t:
        lines = t.read_lines(timeout=2.0)

    boot_lines = [
        line for line in lines if "boot" in line and "ready" in line
    ]
    assert len(boot_lines) == 1, f"expected one boot.ready, got {boot_lines!r}"

    ev = log_parser.parse_line(boot_lines[0] + "\r\n")
    assert ev is not None, boot_lines[0]
    assert ev.module == "boot"
    assert ev.event == "ready"
    assert len(ev.ts_raw) == 8
    assert ev.fields == {}, ev.fields
