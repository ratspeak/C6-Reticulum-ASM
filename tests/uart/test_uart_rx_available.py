"""Tests for src/uart/uart_rx_available.S — non-blocking RX-ready check."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "uart_rx_available") > 0


def test_returns_dr_bit(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_rx_available")
    # `lbu t1, 5(t0)` then `andi a0, t1, 1` — the DR bit becomes a0.
    assert re.search(r"\blbu\b\s+t1,\s*5\(t0\)", body), body
    assert re.search(r"\bandi\b\s+a0,\s*t1,\s*1\b", body), body


def test_no_branches(artifacts: build.BuildArtifacts) -> None:
    """Non-blocking — no loop, no branches."""
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_rx_available")
    for line in body.splitlines():
        assert not re.search(r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|j|jal)\s", line) \
               or "ret" in line or "jalr" in line, line
