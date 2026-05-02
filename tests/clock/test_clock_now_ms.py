"""Tests for src/clock/clock_now_ms.S.

Static: function exists, calls clock_now_ticks, contains a 64-iteration
divisor loop. Integration: drive _main with two KISS frames separated
by a host-side sleep, observe the resulting log timestamps, and assert
the second event's parsed timestamp is strictly greater than the first
(monotonicity) and reflects elapsed wall time.
"""

from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# --- static --------------------------------------------------------------


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "clock_now_ms") > 0


def test_calls_clock_now_ticks(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_now_ms")
    assert "clock_now_ticks" in body, body


def test_loop_iterates_64_times(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_now_ms")
    # The iteration counter is loaded with `li t0, 64` (any tN reg is
    # acceptable — match the literal 64).
    assert re.search(r"\bli\b\s+\w+,\s*64\b", body), \
        f"missing iteration counter init (li ?, 64): {body}"


# --- integration ---------------------------------------------------------


def _run_with_input(elf, stdin_bytes: bytes, *, gap_s: float = 0.0,
                    timeout: float = 2.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        if gap_s > 0:
            time.sleep(gap_s)
        if stdin_bytes:
            t.write(stdin_bytes)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def test_timestamps_monotonic_across_events(
    artifacts: build.BuildArtifacts,
) -> None:
    """boot.ready first, then a kiss.rx_frame triggered by a frame we
    write after pausing on the host. Parser-decoded timestamps must be
    non-decreasing, and the kiss event's ts must exceed boot.ready's."""
    framed = oracle.kiss_encode(b"hello")
    events = _run_with_input(
        artifacts.elf, framed, gap_s=0.10, timeout=1.5
    )

    boot = log_parser.find_event(events, module="boot", event="ready")
    rx = log_parser.find_event(events, module="kiss", event="rx_frame")
    assert boot is not None, [e.raw for e in events]
    assert rx is not None, [e.raw for e in events]

    # Monotonicity is required; the gap should also be visible.
    assert rx.ts_ms >= boot.ts_ms, (boot.raw, rx.raw)
    # Wall gap was 100ms; on a real timer we expect tens of ms minimum.
    # qemu's mtime advances with virtual time so the gap is observable.
    assert rx.ts_ms - boot.ts_ms >= 1, (boot.raw, rx.raw)


def test_timestamp_fits_eight_hex_digits(
    artifacts: build.BuildArtifacts,
) -> None:
    """The wire format is fixed at 8 hex digits per ADR-0008."""
    events = _run_with_input(artifacts.elf, b"", timeout=0.5)
    boot = log_parser.find_event(events, module="boot", event="ready")
    assert boot is not None, [e.raw for e in events]
    assert len(boot.ts_raw) == 8, boot.raw
