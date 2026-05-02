"""Tests for src/kiss/kiss_decode_byte.S.

Two flavours:

* **Static** — the body references the four KISS magic numbers (FEND,
  FESC, TFEND, TFESC), the state symbols, and the buffer; returns the
  three documented status codes (0, 1, -1).
* **Integration (via _main / qemu)** — the boot _main pumps UART RX
  through kiss_decode_byte. We send a sequence of KISS frames and
  oracle-decoded reference frames over qemu's stdin and assert the
  firmware emits one `kiss.rx_frame` log event per frame, plus the
  right number of `kiss.rx_error` events for malformed input.
"""

from __future__ import annotations

import re

import pytest

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# --- static --------------------------------------------------------------


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "kiss_decode_byte") > 0


def test_references_kiss_magic_numbers(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_decode_byte")
    # The function loads each of FEND=0xC0=192, FESC=0xDB=219,
    # TFEND=0xDC=220, TFESC=0xDD=221 as immediates at some point.
    for value in (192, 219, 220, 221):
        assert re.search(rf"\bli\b\s+\w+,\s*{value}\b", body), \
               f"missing li {value}: {body}"


def test_returns_three_distinct_status_codes(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_decode_byte")
    # Exit values: 0 (continue), 1 (frame complete), -1 (error).
    # `li a0, 0` and `li a0, 1` and `li a0, -1` should all appear.
    assert re.search(r"\bli\b\s+a0,\s*0\b", body), body
    assert re.search(r"\bli\b\s+a0,\s*1\b", body), body
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


# --- integration ---------------------------------------------------------


def _run_with_input(
    elf, stdin_bytes: bytes, *, timeout: float = 2.0
) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        if stdin_bytes:
            t.write(stdin_bytes)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def test_one_frame_yields_one_rx_frame_event(
    artifacts: build.BuildArtifacts,
) -> None:
    framed = oracle.kiss_encode(b"hello")
    events = _run_with_input(artifacts.elf, framed)

    boot = log_parser.find_event(events, module="boot", event="ready")
    assert boot is not None, [e.raw for e in events]
    rx = log_parser.find_all(events, module="kiss", event="rx_frame")
    assert len(rx) == 1, [e.raw for e in events]
    err = log_parser.find_all(events, module="kiss", event="rx_error")
    assert err == []


def test_three_frames_back_to_back(artifacts: build.BuildArtifacts) -> None:
    framed = (
        oracle.kiss_encode(b"alpha")
        + oracle.kiss_encode(b"beta")
        + oracle.kiss_encode(b"gamma")
    )
    events = _run_with_input(artifacts.elf, framed)
    rx = log_parser.find_all(events, module="kiss", event="rx_frame")
    assert len(rx) == 3, [e.raw for e in events]


def test_escape_sequences_round_trip(artifacts: build.BuildArtifacts) -> None:
    """Payload with a literal FEND and FESC byte gets escaped on the
    wire; the decoder must un-escape and produce one frame."""
    payload = bytes([0xC0, 0xDB, 0x42, 0xC0])
    framed = oracle.kiss_encode(payload)
    events = _run_with_input(artifacts.elf, framed)
    rx = log_parser.find_all(events, module="kiss", event="rx_frame")
    assert len(rx) == 1, [e.raw for e in events]
    assert log_parser.find_all(events, module="kiss", event="rx_error") == []


def test_bad_escape_emits_rx_error(artifacts: build.BuildArtifacts) -> None:
    """FESC followed by neither TFEND nor TFESC is a framing error.
    The decoder resets and reports rx_error; subsequent valid frames
    still parse."""
    bad = bytes([0xC0, 0x00, 0xDB, 0x99, 0xC0])  # bad escape inside frame
    good = oracle.kiss_encode(b"after")
    events = _run_with_input(artifacts.elf, bad + good)
    err = log_parser.find_all(events, module="kiss", event="rx_error")
    assert len(err) >= 1, [e.raw for e in events]
    rx = log_parser.find_all(events, module="kiss", event="rx_frame")
    assert len(rx) >= 1, [e.raw for e in events]
