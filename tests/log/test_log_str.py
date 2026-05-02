"""Tests for src/log/log_str.S — tail-call into uart_tx_bytes."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_str") > 0


def test_tail_calls_uart_tx_bytes(artifacts: build.BuildArtifacts) -> None:
    """Body is a single tail-call: auipc/jalr to uart_tx_bytes (no frame
    setup, no ra save). The target symbol comment must reference
    uart_tx_bytes."""
    body = build.objdump_disassemble(artifacts.elf, symbol="log_str")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    # `tail uart_tx_bytes` → auipc t1, ... ; jalr zero, off(t1) (or jr).
    # Compressed forms are also possible (`c.j`, `c.jr`).
    assert "uart_tx_bytes" in body, body
    # No stack adjust: no `addi sp, sp, …` should appear.
    for line in instrs:
        assert not re.search(r"\baddi\s+sp", line), line


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_str")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"log_str writes callee-saved {match}: {body}")
