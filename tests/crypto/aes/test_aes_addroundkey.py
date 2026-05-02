"""Static tests for src/crypto/aes/aes_addroundkey.S.

End-to-end correctness covered by aes256_encrypt_block KAT.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_addroundkey") > 0


def test_uses_word_xor_pattern(artifacts: build.BuildArtifacts) -> None:
    """Should be 4 unrolled (lw, lw, xor, sw) groups — 16 instructions
    plus ret."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_addroundkey")
    assert len(re.findall(r"\blw\b", body)) >= 8
    assert len(re.findall(r"\bxor\b", body)) >= 4
    assert len(re.findall(r"\bsw\b", body)) >= 4


def test_no_branches(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_addroundkey")
    branches = re.findall(
        r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bltz|bgtz|j|jr|jal)\b",
        body,
    )
    # Allow `ret` (a jr alias) at the end. Reject any beq/bne/etc.
    bad = [b for b in branches if b not in {"jr", "j"}]
    assert bad == [], f"unexpected control flow {bad}"
