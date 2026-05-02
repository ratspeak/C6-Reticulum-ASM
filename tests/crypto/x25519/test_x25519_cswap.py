"""Static checks for src/crypto/x25519/x25519_cswap.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_cswap") > 0


def test_no_branches(artifacts):
    """Branch-free for constant-time."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_cswap")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches in cswap: {branches}"


def test_uses_subtract_for_mask(artifacts):
    """Mask is computed as -swap (zero - swap). Disassembler may render
    `sub a0, zero, a0` as the pseudo `neg a0, a0`."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_cswap")
    assert (re.search(r"\bsub\b\s+a0,\s*zero,\s*a0", body)
            or re.search(r"\bneg\b\s+a0,\s*a0", body)), \
        f"missing `sub/neg a0, zero/a0, a0`: {body}"


def test_unrolled_ten_pairs(artifacts):
    """Ten unrolled pairs: 20 lw, 20 sw, 30 xor (a^b, a^=diff, b^=diff), 10 and."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_cswap")
    assert len(re.findall(r"\blw\b", body)) == 20
    assert len(re.findall(r"\bsw\b", body)) == 20
    assert len(re.findall(r"\bxor\b", body)) == 30
    assert len(re.findall(r"\band\b", body)) == 10
