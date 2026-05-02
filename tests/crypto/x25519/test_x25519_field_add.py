"""Static checks for src/crypto/x25519/x25519_field_add.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_add") > 0


def test_no_branches(artifacts):
    """Pointwise add must be straight-line — no conditional branches."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_add")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches in field_add: {branches}"


def test_unrolled_ten_pairs(artifacts):
    """Ten pointwise adds — expect 10 lw of a (offsets 0,4,...,36 from a1),
    10 lw of b, 10 add, 10 sw to a0."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_add")
    lw_count  = len(re.findall(r"\blw\b", body))
    add_count = len(re.findall(r"\badd\b\s+t0,t0,t1", body))
    sw_count  = len(re.findall(r"\bsw\b", body))
    # 10 lw a + 10 lw b = 20 lw
    assert lw_count == 20, f"expected 20 lw, got {lw_count}"
    assert sw_count == 10, f"expected 10 sw, got {sw_count}"
    assert add_count == 10, f"expected 10 add t0,t0,t1, got {add_count}"
