"""Tests for src/crypto/sha256/sha256_update.S.

Static-only: function exists, calls sha256_compress, references
SHA256_BLOCK_SIZE (64), and increments the 64-bit length counter
correctly.

End-to-end correctness lands once a sha256 chain test ELF (init →
update → final → digest dump) exists.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_update") > 0


def test_calls_sha256_compress(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_update")
    assert "sha256_compress" in body, body


def test_references_block_size_64(artifacts: build.BuildArtifacts) -> None:
    """Either as a literal `li ?, 64` (block-size compare) or as the
    `addi ?, ?, -64` after-compress decrement."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_update")
    has_block_size = bool(
        re.search(r"\bli\b\s+\w+,\s*64\b", body)
        or re.search(r"\baddi\b\s+\w+,\s*\w+,\s*-64\b", body)
    )
    assert has_block_size, f"missing block-size constant: {body}"


def test_64bit_length_accumulate_uses_sltu(
    artifacts: build.BuildArtifacts,
) -> None:
    """The carry-from-low calculation in the length-bits update needs
    `sltu` to detect 32-bit overflow."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_update")
    assert re.search(r"\bsltu\b", body), \
        f"missing sltu (carry compute): {body}"


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    """s0..s5 are spilled per the spec block."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_update")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(6)}.issubset(saved), \
        f"expected s0..s5 saved, saw {saved}"
