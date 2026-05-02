"""Static tests for src/crypto/hmac/hmac_sha256.S.

End-to-end correctness against RFC 4231 vectors lives in
test_hmac_kat.py (drives _main with the 'H' marker).
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "hmac_sha256") > 0


def test_calls_sha256_chain(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_sha256")
    for callee in ("sha256_init", "sha256_update", "sha256_final"):
        assert callee in body, f"{callee} not called: {body}"


def test_uses_ipad_xor_constants(artifacts: build.BuildArtifacts) -> None:
    """0x36 (ipad) and 0x6A (ipad ^ opad) must appear as immediates."""
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_sha256")
    assert re.search(r"\bli\b\s+\w+,\s*54\b", body) \
        or re.search(r"\bli\b\s+\w+,\s*0x36\b", body), \
        f"missing ipad byte 0x36: {body}"
    assert re.search(r"\bli\b\s+\w+,\s*106\b", body) \
        or re.search(r"\bli\b\s+\w+,\s*0x6a\b", body), \
        f"missing ipad^opad byte 0x6A: {body}"


def test_block_size_64(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_sha256")
    assert re.search(r"\bli\b\s+\w+,\s*64\b", body), body


def test_buffers_present(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "hmac_key_prep") > 0
    assert build.symbol_address(artifacts.elf, "hmac_inner_tag") > 0


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_sha256")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(5)}.issubset(saved), \
        f"expected s0..s4 saved, saw {saved}"
