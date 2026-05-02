"""Static tests for aes_subbytes + aes_invsubbytes.

End-to-end correctness covered by the encrypt_block / decrypt_block KATs.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_subbytes_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_subbytes") > 0


def test_invsubbytes_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_invsubbytes") > 0


def test_subbytes_calls_sbox(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_subbytes")
    assert "aes_sbox" in body, body
    # Must NOT call the inverse.
    assert "aes_invsbox" not in body, body


def test_invsubbytes_calls_invsbox(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invsubbytes")
    assert "aes_invsbox" in body, body


def test_subbytes_loop_count_is_16(artifacts: build.BuildArtifacts) -> None:
    """The loop end is computed as base + AES_BLOCK_SIZE (=16). The
    block-size constant 16 should appear as an immediate."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_subbytes")
    assert re.search(r"\baddi\b\s+s1\s*,\s*\w+\s*,\s*16\b", body), body


def test_invsubbytes_loop_count_is_16(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invsubbytes")
    assert re.search(r"\baddi\b\s+s1\s*,\s*\w+\s*,\s*16\b", body), body
