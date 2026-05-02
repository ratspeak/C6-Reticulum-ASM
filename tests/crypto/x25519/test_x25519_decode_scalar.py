"""Static checks for src/crypto/x25519/x25519_decode_scalar.S."""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_decode_scalar") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_decode_scalar")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_uses_clamp_constants(artifacts):
    """Should mask byte 0 with 248 and byte 31 with 127 / 64."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_decode_scalar")
    # Disassemblers may render the constants in either decimal or hex.
    assert re.search(r"\bandi\b\s+\w+,\s*\w+,\s*(248|0xf8|-8)", body), \
        f"missing andi with 248: {body}"
    assert re.search(r"\bandi\b\s+\w+,\s*\w+,\s*(127|0x7f)", body), \
        f"missing andi with 127: {body}"
    assert re.search(r"\bori\b\s+\w+,\s*\w+,\s*(64|0x40)", body), \
        f"missing ori with 64: {body}"
