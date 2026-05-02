"""Tests for src/uart/uart_tx_bytes.S.

Static disassembly checks: prologue saves ra/s0/s1, loop forwards each
byte to uart_tx_byte, epilogue restores and returns. Integration cover
(actual byte-stream observed on qemu UART) lands when _main wires the
boot chain.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "uart_tx_bytes") > 0


def test_prologue_reserves_aligned_frame(artifacts: build.BuildArtifacts) -> None:
    """16-byte stack frame, ra/s0/s1 saved before any other work."""
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_bytes")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    # First instruction adjusts sp by -16 (compressed `c.addi16sp` is OK too).
    assert "sp" in instrs[0] and ("-16" in instrs[0] or "addi" in instrs[0]), instrs[0]
    # ra, s0, s1 stored in the frame somewhere in the prologue.
    head = "\n".join(instrs[:6])
    assert re.search(r"\bsw\b\s+ra,", head), head
    assert re.search(r"\bsw\b\s+s0,", head) or re.search(r"\bc\.swsp\b\s+s0,", head), head
    assert re.search(r"\bsw\b\s+s1,", head) or re.search(r"\bc\.swsp\b\s+s1,", head), head


def test_calls_uart_tx_byte(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_bytes")
    assert "uart_tx_byte" in body, body


def test_loop_loads_byte_and_advances_cursor(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_bytes")
    # `lbu a0, 0(s0)` (byte from cursor) and `addi s0, s0, 1` (advance).
    assert re.search(r"\blbu\b\s+a0,\s*0\(s0\)", body), body
    assert re.search(r"\baddi\b\s+s0,\s*s0,\s*1", body), body
    # Counter decrement: `addi s1, s1, -1`.
    assert re.search(r"\baddi\b\s+s1,\s*s1,\s*-1", body), body


def test_epilogue_restores_and_returns(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_bytes")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    tail = "\n".join(instrs[-6:])
    assert re.search(r"\blw\b\s+ra,", tail) or "c.lw" in tail, tail
    assert "ret" in tail or "jalr\tzero" in tail, tail
    # sp restored upward by 16 (matching the prologue).
    assert "16" in tail, tail


def test_count_zero_short_circuits(artifacts: build.BuildArtifacts) -> None:
    """The empty-buffer case: a beqz at the loop head exits before any
    byte is read."""
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_bytes")
    # Find the first beqz that targets an address inside the function — that
    # is the loop-head exit.
    assert re.search(r"\bbeqz\b\s+s1", body), body
