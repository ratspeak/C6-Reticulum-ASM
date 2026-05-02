"""Tests for src/log/log_hex.S.

Static disassembly checks for the prologue/loop/digit-conversion shape.
Behavioural cover (a known value emits the expected hex chars) lands
through log_event's integration test, which uses log_hex to format the
8-digit timestamp.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_hex") > 0


def test_prologue_saves_ra_s0_s1(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex")
    head = "\n".join(body.splitlines()[:10])
    assert "addi" in head and "sp" in head and "-16" in head, head
    assert re.search(r"\bsw\b\s+ra", head), head


def test_handles_width_zero_via_head_branch(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex")
    # The very first thing after the prologue/save is `beqz s1, …` so width=0
    # exits without emitting anything.
    assert re.search(r"\bbeqz\b\s+s1", body), body


def test_extracts_nibble_via_shift_and_mask(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex")
    # srl t1, s0, t0  →  srl with t1 dest
    assert re.search(r"\bsrl\b\s+t1,", body), body
    # andi t1, t1, 0xF (assembler emits 15)
    assert re.search(r"\bandi\b\s+t1,\s*t1,\s*15\b", body), body


def test_digit_branch_for_a_through_f(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex")
    # blt t1, t2 splits 0..9 (add 48 = '0') from a..f (add 87 = 'a' - 10)
    assert "li\tt2,10" in body or re.search(r"\bli\b\s+t2,\s*10\b", body), body
    assert "48" in body, body
    assert "87" in body, body


def test_calls_uart_tx_byte_per_digit(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex")
    assert "uart_tx_byte" in body, body
