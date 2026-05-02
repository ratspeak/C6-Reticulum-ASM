"""Static checks for src/crypto/x25519/x25519_field_pack.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_pack") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_pack")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_uses_byte_stores(artifacts):
    """Pack writes 32 individual bytes to the output buffer."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_pack")
    sb_count = len(re.findall(r"\bsb\b", body))
    assert sb_count >= 32, f"expected ≥32 sb instructions, got {sb_count}"


def test_uses_signed_shift(artifacts):
    """Carry propagation must be arithmetic (signed) so negative limbs
    propagate borrow correctly into the next limb."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_pack")
    assert re.search(r"\bsrai\b", body), f"missing srai (signed shift): {body}"


def test_loads_p_limb_0_constant(artifacts):
    """The conditional-subtract step uses p[0] = 2^26 - 19 = 0x3FFFFED.
    The asm derives this as `addi t5, a2, -18` from a2 = MASK_26
    (since (MASK_26 + 1) - 19 = MASK_26 - 18)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_pack")
    has_p0 = bool(
        re.search(r"\baddi\b\s+\w+,\s*\w+,\s*-18\b", body)
        or re.search(r"\b0x3ffffed\b", body, re.IGNORECASE)
        or re.search(r"\b67108845\b", body)
    )
    assert has_p0, f"missing p[0] = 0x3FFFFED derivation: {body}"


def test_stack_frame_balanced(artifacts):
    """sp must be restored before ret."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_pack")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments found: {body}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp adjustments: {allocs} (net {net})"
