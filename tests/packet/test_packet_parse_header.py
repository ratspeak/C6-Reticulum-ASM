"""Tests for src/packet/packet_parse_header.S.

Static checks plus an integration test through the full bring-up
pipeline (UART RX → kiss_decode_byte → packet_parse_header → log).
The integration test sends KISS-framed Reticulum-shaped packets via
qemu's stdin and asserts the firmware's log output identifies them as
parsed (HEADER_1 + minimum-length packet) or rejected (truncated).
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
    assert build.symbol_address(artifacts.elf, "packet_parse_header") > 0


def test_truncated_returns_minus_one(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_parse_header")
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


def test_header_minsize_check(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_parse_header")
    # HEADER_MINSIZE = 19; loaded as immediate then compared with raw_len.
    assert re.search(r"\bli\b\s+\w+,\s*19\b", body), body


def test_writes_struct_fields(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_parse_header")
    # The function must store at offsets 0, 1, 2, 3 (header, hops, header_type,
    # packet_type) and at offsets 4, 8, 12, 16 (dest_hash_off, payload_off,
    # payload_len, raw_len) and 20 (raw_ptr).
    sb_offsets = re.findall(r"\bsb\b\s+\w+,\s*(\d+)\(a2\)", body)
    sh_offsets = re.findall(r"\bsh\b\s+\w+,\s*(\d+)\(a2\)", body)
    sw_offsets = re.findall(r"\bsw\b\s+\w+,\s*(\d+)\(a2\)", body)
    assert {"0", "1", "2", "3"}.issubset(set(sb_offsets)), sb_offsets
    assert {"4", "8", "12", "16"}.issubset(set(sh_offsets)), sh_offsets
    assert "20" in sw_offsets, sw_offsets


# --- integration through _main ------------------------------------------


def _run(elf, stdin_bytes: bytes, *, timeout: float = 2.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        if stdin_bytes:
            t.write(stdin_bytes)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _minimal_h1_packet(packet_type: int = 0x01) -> bytes:
    """A 19-byte HEADER_1 packet: flags + hops + 16-byte hash + 1 ctx byte."""
    flags = packet_type & 0x03
    return bytes([flags, 0x00]) + b"h" * 16 + bytes([0x00])


def test_minimum_h1_packet_is_parsed(artifacts: build.BuildArtifacts) -> None:
    framed = oracle.kiss_encode(_minimal_h1_packet())
    events = _run(artifacts.elf, framed)
    assert log_parser.find_event(events, module="kiss", event="rx_frame")
    assert log_parser.find_event(events, module="packet", event="parsed"), \
        [e.raw for e in events]


def test_short_packet_is_rejected(artifacts: build.BuildArtifacts) -> None:
    """A 5-byte payload is shorter than HEADER_MINSIZE (19)."""
    framed = oracle.kiss_encode(b"shrt!")
    events = _run(artifacts.elf, framed)
    assert log_parser.find_event(events, module="kiss", event="rx_frame")
    assert log_parser.find_event(events, module="packet", event="rejected"), \
        [e.raw for e in events]


def test_three_packets_three_parses(artifacts: build.BuildArtifacts) -> None:
    framed = b"".join(
        oracle.kiss_encode(_minimal_h1_packet(packet_type=t))
        for t in (0x00, 0x01, 0x02)
    )
    events = _run(artifacts.elf, framed)
    parsed = log_parser.find_all(events, module="packet", event="parsed")
    assert len(parsed) == 3, [e.raw for e in events]
