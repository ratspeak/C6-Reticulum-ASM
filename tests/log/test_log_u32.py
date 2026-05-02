"""Tests for src/log/log_u32.S.

Static disassembly checks. Integration cover (running the function on
known values in qemu) lands when a per-function test-firmware path is
added; for now, log_u32 ships with shape-level guarantees and will
participate in future regression once log_event-style tests exercise it.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_u32") > 0


def test_uses_div_and_rem(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_u32")
    assert re.search(r"\bdiv\b", body), body
    assert re.search(r"\brem\b", body), body


def test_handles_zero_specifically(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_u32")
    # The early `beqz a0, .Lzero` short-circuit must exist; otherwise
    # value=0 produces an empty string.
    assert re.search(r"\bbeqz\b\s+a0", body), body


def test_emit_loop_calls_uart_tx_byte(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_u32")
    assert "uart_tx_byte" in body, body


def test_frame_aligned_to_16(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_u32")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    # First instruction adjusts sp by -32.
    assert "sp" in instrs[0] and "-32" in instrs[0], instrs[0]
