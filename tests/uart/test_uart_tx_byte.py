"""Tests for src/uart/uart_tx_byte.S.

Static disassembly checks: the body matches the NS16550A polled-TX shape
(load UART0_BASE → spin on LSR.THRE → store a0 to THR → ret). The
integration test (firmware emits a known byte, EmuTarget reads it from
qemu's serial) lands once _main is wired.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "uart_tx_byte") > 0


def test_loads_uart0_base(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_byte")
    # `li t0, UART0_BASE` (0x10000000) → assembler emits `lui t0, 0x10000`
    # since the base has zero low 12 bits.
    assert re.search(r"\blui\b\s+t0,\s*0x10000\b", body), body


def test_polls_lsr_and_masks_thre(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_byte")
    # Read LSR at offset 5, AND with 0x20 (THRE), branch back if zero.
    assert re.search(r"\blbu\b\s+t1,\s*5\(t0\)", body), body
    assert re.search(r"\bandi\b\s+t1,\s*t1,\s*32\b", body), body
    assert re.search(r"\bbeqz\b\s+t1", body), body


def test_writes_byte_to_thr(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_byte")
    # Store argument byte (a0) to THR (offset 0 from base).
    assert re.search(r"\bsb\b\s+a0,\s*0\(t0\)", body), body


def test_returns(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_byte")
    assert "ret" in body or "jalr\tzero" in body


def test_does_not_touch_callee_saved_or_a0(artifacts: build.BuildArtifacts) -> None:
    """ABI: a0 carries the input and is not modified; s0..s11 are not touched."""
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_tx_byte")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"uart_tx_byte writes callee-saved {match}: {body}")
    # a0 only appears as the source of the sb (read), never as a destination.
    for line in body.splitlines():
        m = re.search(r"^\s*[0-9a-f]{8}:\s+\S+\s+(\w+)\s+(a0)\b", line)
        if m and m.group(1) not in {"sb", "sh", "sw"}:
            pytest.fail(f"uart_tx_byte writes a0: {line}")
