"""Tests for src/uart/uart_init.S.

On qemu-virt the body is `ret` — qemu's NS16550A model self-initialises.
The integration cover (sending a byte after init lands in qemu's UART
output) lives in test_uart_tx_byte.py.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "uart_init") > 0


def test_qemu_virt_body_is_just_return(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_init")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    assert len(instrs) == 1, body
    assert "ret" in instrs[0] or "jalr\tzero" in instrs[0], instrs[0]


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_init")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"uart_init writes callee-saved {match}: {body}")
