"""Static tests for aes_shiftrows + aes_invshiftrows.

End-to-end correctness covered by the encrypt_block / decrypt_block KATs.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_shiftrows_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_shiftrows") > 0


def test_invshiftrows_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_invshiftrows") > 0


def test_shiftrows_no_branches(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_shiftrows")
    branches = re.findall(
        r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bltz|bgtz)\b",
        body,
    )
    assert branches == [], f"unexpected branches {branches}"


def test_invshiftrows_no_branches(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invshiftrows")
    branches = re.findall(
        r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bltz|bgtz)\b",
        body,
    )
    assert branches == [], f"unexpected branches {branches}"


def test_shiftrows_uses_word_stores(artifacts: build.BuildArtifacts) -> None:
    """The implementation builds 4 new words and writes them; expect 4 sw."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_shiftrows")
    sws = re.findall(r"\bsw\b", body)
    assert len(sws) >= 4, f"expected at least 4 word stores, got {len(sws)}"


def test_invshiftrows_uses_word_stores(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invshiftrows")
    sws = re.findall(r"\bsw\b", body)
    assert len(sws) >= 4, f"expected at least 4 word stores, got {len(sws)}"


def test_shiftrows_loads_all_16_bytes(
    artifacts: build.BuildArtifacts,
) -> None:
    """Should perform exactly 16 byte loads (one per source byte)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_shiftrows")
    lbus = re.findall(r"\blbu\b", body)
    assert len(lbus) == 16, f"expected 16 lbus, got {len(lbus)}"


def test_invshiftrows_loads_all_16_bytes(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invshiftrows")
    lbus = re.findall(r"\blbu\b", body)
    assert len(lbus) == 16, f"expected 16 lbus, got {len(lbus)}"
