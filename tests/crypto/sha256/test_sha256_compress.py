"""Tests for src/crypto/sha256/sha256_compress.S.

Static-only for now: function exists, references the K table, the K
table itself contains the 64 FIPS 180-4 §4.2.2 round constants in the
correct order, and the body contains the three expected loops
(W[0..15] BE load, W[16..63] schedule, 64-round main).

End-to-end correctness against FIPS 180-4 §B.1 ("abc" one-block test)
lands once a sha256 test path through `_main` exists — that requires
sha256_init + sha256_update + sha256_final to be wired together. The
static checks below rule out the most likely structural regressions
(wrong K table, missing schedule loop, wrong round count).
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from harness import build

# FIPS 180-4 §4.2.2 — first 32 bits of the fractional parts of the cube
# roots of the first 64 primes. Order matters.
SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _read_bytes_at(elf, addr: int, length: int) -> bytes:
    """Pull `length` bytes starting at `addr` from the ELF via objdump -s."""
    if shutil.which("riscv64-elf-objdump") is None:
        pytest.skip("riscv64-elf-objdump not on PATH")
    proc = subprocess.run(
        [
            "riscv64-elf-objdump", "-s",
            f"--start-address=0x{addr:x}",
            f"--stop-address=0x{addr + length:x}",
            str(elf),
        ],
        capture_output=True, text=True, check=True,
    )
    out = bytearray()
    line_re = re.compile(r"^\s+([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s*)+?)\s{2}")
    for line in proc.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        for chunk in m.group(2).split():
            for i in range(0, len(chunk), 2):
                out.append(int(chunk[i:i + 2], 16))
    return bytes(out[:length])


# --- static --------------------------------------------------------------


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_compress") > 0


def test_k_table_symbol_present(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_k") > 0


def test_k_table_bytes_match_fips(artifacts: build.BuildArtifacts) -> None:
    """The 64 K constants must match FIPS 180-4 §4.2.2 in order."""
    addr = build.symbol_address(artifacts.elf, "sha256_k")
    raw = _read_bytes_at(artifacts.elf, addr, 256)
    assert len(raw) == 256, f"sha256_k: got {len(raw)} bytes, want 256"
    words = tuple(
        int.from_bytes(raw[i:i + 4], "little") for i in range(0, 256, 4)
    )
    assert words == SHA256_K, \
        f"K table mismatch at index {next(i for i,(a,b) in enumerate(zip(words, SHA256_K)) if a != b)}"


def test_body_references_k_table(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_compress")
    assert "sha256_k" in body, body


def test_body_has_three_loops(artifacts: build.BuildArtifacts) -> None:
    """W[0..15] big-endian load, W[16..63] schedule, 64-round main —
    each is a labelled back-edge branch in the disassembly."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_compress")
    # Count back-edge branches (bnez/bne whose immediate is negative
    # relative to the next pc — objdump renders them as `bnez ?, <addr>`
    # where addr is earlier in the function).
    branches = re.findall(r"\b(?:bnez|bne)\b\s+\w+", body)
    assert len(branches) >= 3, f"expected ≥3 loops, got {branches}: {body}"


def test_round_count_is_64(artifacts: build.BuildArtifacts) -> None:
    """Main loop terminates at offset 256 (= 64 rounds × 4 bytes)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_compress")
    assert re.search(r"\bli\b\s+\w+,\s*256\b", body), \
        f"missing loop terminator `li ?, 256`: {body}"


def test_stack_frame_size(artifacts: build.BuildArtifacts) -> None:
    """Frame is 304 bytes per the spec block. Function-entry `addi sp, sp, -304`
    with matching `addi sp, sp, 304` epilogue."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_compress")
    assert re.search(r"\baddi\b\s+sp,\s*sp,\s*-304\b", body), body
    assert re.search(r"\baddi\b\s+sp,\s*sp,\s*304\b", body), body


def test_saves_and_restores_callee_saved(
    artifacts: build.BuildArtifacts,
) -> None:
    """s0..s8 must be spilled and restored — 9 sw + 9 lw of s-regs."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_compress")
    sw_s = re.findall(r"\bsw\b\s+(s\d+)\b", body)
    lw_s = re.findall(r"\blw\b\s+(s\d+)\b", body)
    saved = set(sw_s)
    restored = set(lw_s)
    assert {f"s{i}" for i in range(9)}.issubset(saved), f"saves: {saved}"
    assert {f"s{i}" for i in range(9)}.issubset(restored), f"restores: {restored}"
