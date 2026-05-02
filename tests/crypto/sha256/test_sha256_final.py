"""Tests for src/crypto/sha256/sha256_final.S.

Static-only: function exists, calls sha256_compress (at least once for
the trailing block; potentially twice if padding overflows), writes a
0x80 byte (the FIPS 180-4 §5.1.1 padding marker), and emits the
big-endian length and digest.

End-to-end correctness lands once the sha256 chain test ELF is in place.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_final") > 0


def test_calls_sha256_compress(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_final")
    assert "sha256_compress" in body, body


def test_writes_padding_marker_0x80(artifacts: build.BuildArtifacts) -> None:
    """FIPS 180-4 §5.1.1: append 0x80 then zero padding."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_final")
    assert re.search(r"\bli\b\s+\w+,\s*128\b", body) \
        or re.search(r"\bli\b\s+\w+,\s*0x80\b", body), \
        f"missing 0x80 padding marker: {body}"


def test_pad_threshold_is_56(artifacts: build.BuildArtifacts) -> None:
    """If block_len > 56 the padding overflows and a second compress is
    needed. The threshold appears as `li ?, 56`."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_final")
    assert re.search(r"\bli\b\s+\w+,\s*56\b", body), \
        f"missing 56-byte threshold: {body}"


def test_emits_big_endian_bytes(artifacts: build.BuildArtifacts) -> None:
    """BE byte emission shows up as `srli` by 24/16/8 + `sb`."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_final")
    for shift in (24, 16, 8):
        assert re.search(rf"\bsrli\b\s+\w+,\s*\w+,\s*0x{shift:x}\b", body) \
            or re.search(rf"\bsrli\b\s+\w+,\s*\w+,\s*{shift}\b", body), \
            f"missing srli by {shift} (BE byte extract): {body}"


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_final")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(3)}.issubset(saved), \
        f"expected s0..s2 saved, saw {saved}"
