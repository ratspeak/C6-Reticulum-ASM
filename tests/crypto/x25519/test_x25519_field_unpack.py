"""Static checks for src/crypto/x25519/x25519_field_unpack.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_unpack") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_unpack")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_uses_byte_loads(artifacts):
    """Should use lbu (byte loads) for alignment-safety; 4 per limb × 10 limbs = 40 lbu."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_unpack")
    lbu = re.findall(r"\blbu\b", body)
    assert len(lbu) == 40, f"expected 40 lbu, got {len(lbu)}"


def test_writes_ten_limbs(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_unpack")
    sw = re.findall(r"\bsw\b", body)
    assert len(sw) == 10, f"expected 10 sw, got {len(sw)}"
