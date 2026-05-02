"""Static checks for src/crypto/x25519/x25519_field_mul121665.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_mul121665") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul121665")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_uses_mul_and_mulh(artifacts):
    """64-bit signed product needs mul (low) + mulh (signed high)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul121665")
    assert re.search(r"\bmul\b", body), f"missing mul: {body}"
    assert re.search(r"\bmulh\b", body), f"missing mulh: {body}"


def test_loads_scalar_constant(artifacts):
    """li ?, 121665 (= 0x1DB41) somewhere; assembler may render as
    `li reg, 0x1db41` or `li reg, 121665` or split into lui+addi."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul121665")
    has_constant = bool(
        re.search(r"\b121665\b", body)
        or re.search(r"\b0x1db41\b", body, re.IGNORECASE)
        or re.search(r"\blui\b\s+\w+,\s*0x1[eE]?\b", body)  # lui takes top 20 bits
    )
    assert has_constant, f"missing scalar constant 121665: {body}"
