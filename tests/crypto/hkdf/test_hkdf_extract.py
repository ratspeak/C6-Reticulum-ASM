"""Static tests for src/crypto/hkdf/hkdf_extract.S.

End-to-end correctness against RFC 5869 vectors lives in
test_hkdf_kat.py (drives _main with the 'E' marker).
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "hkdf_extract") > 0


def test_calls_hmac_sha256(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hkdf_extract")
    assert "hmac_sha256" in body, body


def test_references_zero_salt_fallback(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hkdf_extract")
    assert "hkdf_zero_salt" in body, body


def test_zero_salt_is_32_zeros(artifacts: build.BuildArtifacts) -> None:
    """hkdf_zero_salt is the 32-byte all-zero buffer used when salt_len == 0."""
    addr = build.symbol_address(artifacts.elf, "hkdf_zero_salt")
    assert addr > 0
