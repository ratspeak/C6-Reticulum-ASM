"""Static tests for src/crypto/hkdf/hkdf_expand.S.

End-to-end correctness against RFC 5869 vectors lives in test_hkdf_kat.py.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "hkdf_expand") > 0


def test_calls_hmac_sha256(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hkdf_expand")
    assert "hmac_sha256" in body, body


def test_buffers_present_in_elf(artifacts: build.BuildArtifacts) -> None:
    """The scratch buffers exist; whether the disassembly comment names
    them depends on addressing mode (gp-relative loses the comment),
    so we just check the symbols resolve."""
    assert build.symbol_address(artifacts.elf, "hkdf_msg_buf") > 0
    assert build.symbol_address(artifacts.elf, "hkdf_t_buf") > 0


def test_uses_hash_len_constant(artifacts: build.BuildArtifacts) -> None:
    """The 32-byte HashLen appears as a literal in the truncation logic."""
    body = build.objdump_disassemble(artifacts.elf, symbol="hkdf_expand")
    assert re.search(r"\bli\b\s+\w+,\s*32\b", body), body


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hkdf_expand")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(7)}.issubset(saved), \
        f"expected s0..s6 saved, saw {saved}"
