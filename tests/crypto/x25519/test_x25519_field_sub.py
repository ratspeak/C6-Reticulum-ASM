"""Static checks for src/crypto/x25519/x25519_field_sub.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_sub") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_sub")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches in field_sub: {branches}"


def test_unrolled_ten_pairs(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_sub")
    lw_count  = len(re.findall(r"\blw\b", body))
    sub_count = len(re.findall(r"\bsub\b\s+t0,t0,t1", body))
    sw_count  = len(re.findall(r"\bsw\b", body))
    assert lw_count == 20, f"expected 20 lw, got {lw_count}"
    assert sw_count == 10, f"expected 10 sw, got {sw_count}"
    assert sub_count == 10, f"expected 10 sub t0,t0,t1, got {sub_count}"
