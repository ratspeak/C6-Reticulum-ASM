"""Static + KAT tests for src/crypto/aes/aes_invsbox.S.

Implementation strategy validated here:

    iS(x) = A( S( A(x) ) )    where  A(x) = rol8(x,6) ^ rol8(x,3) ^ rol8(x,1) ^ 0x05

This is the Saarinen identity used by BearSSL's bit-sliced inverse S-box.
A single forward S-box plus two affine transforms (each ~16 RV32 ops) is
much cheaper than a second 113-gate Boyar-Peralta circuit, and inherits
its constant-time property automatically.

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


# FIPS 197 §B / Figure 14 — AES inverse S-box (256 entries).
INV_SBOX = bytes((
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
))
assert len(INV_SBOX) == 256


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_invsbox") > 0


def test_calls_aes_sbox(artifacts: build.BuildArtifacts) -> None:
    """aes_invsbox is implemented as A(S(A(x))); the disassembly must
    reference aes_sbox exactly once."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invsbox")
    n_calls = len(re.findall(r"\baes_sbox\b", body))
    assert n_calls == 1, (
        f"expected exactly one aes_sbox reference, got {n_calls}"
    )


def test_no_branches_on_data(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invsbox")
    branches = re.findall(r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bltz|bgtz)\b",
                          body)
    assert branches == [], (
        f"aes_invsbox must be branch-free; found {branches}"
    )


def test_uses_xori_05(artifacts: build.BuildArtifacts) -> None:
    """The pre- and post-affine each fold in `xori reg, reg, 5`.
    Two such instructions are required."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invsbox")
    occurrences = re.findall(r"\bxori\b\s+\w+\s*,\s*\w+\s*,\s*5\b", body)
    assert len(occurrences) >= 2, (
        f"expected 2+ `xori _, _, 5` (pre and post affine constant), "
        f"found {len(occurrences)}"
    )


# ---------- KAT (full 256-byte map) ----------

def _run_with_input(elf, stdin_bytes: bytes, *, gap_s: float = 0.05,
                    timeout: float = 6.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        if gap_s > 0:
            time.sleep(gap_s)
        if stdin_bytes:
            t.write(stdin_bytes)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def test_full_invsbox_kat(artifacts: build.BuildArtifacts) -> None:
    """Send all 256 input bytes through aes_invsbox; the response must
    match FIPS 197 Figure 14 exactly."""
    inputs = bytes(range(256))
    payload = b"I" + inputs
    framed = oracle.kiss_encode(payload)
    events = _run_with_input(artifacts.elf, framed)

    sb = log_parser.find_event(events, module="aes", event="invsbox")
    assert sb is not None, [e.raw for e in events]
    got_hex = sb.fields.get("hex", "")
    assert len(got_hex) == 512, (
        f"expected 512 hex chars (256 bytes), got {len(got_hex)}"
    )
    got = bytes.fromhex(got_hex)
    diffs = [(i, got[i], INV_SBOX[i]) for i in range(256)
             if got[i] != INV_SBOX[i]]
    assert not diffs, (
        f"inv-S-box mismatch at {len(diffs)} of 256 inputs; first diffs: "
        + ", ".join(f"in={i:02x} got={g:02x} want={w:02x}"
                    for i, g, w in diffs[:8])
    )


def test_round_trip(artifacts: build.BuildArtifacts) -> None:
    """invSbox(Sbox(x)) == x for every byte. Done as two consecutive
    runs (one per primitive) and zip-comparison of the raw responses."""
    inputs = bytes(range(256))
    fwd_events = _run_with_input(artifacts.elf,
                                 oracle.kiss_encode(b"B" + inputs))
    fwd = log_parser.find_event(fwd_events, module="aes", event="sbox")
    assert fwd is not None, [e.raw for e in fwd_events]
    fwd_bytes = bytes.fromhex(fwd.fields["hex"])

    rev_events = _run_with_input(artifacts.elf,
                                 oracle.kiss_encode(b"I" + fwd_bytes))
    rev = log_parser.find_event(rev_events, module="aes", event="invsbox")
    assert rev is not None, [e.raw for e in rev_events]
    rev_bytes = bytes.fromhex(rev.fields["hex"])

    assert rev_bytes == inputs, (
        "round trip invSbox(Sbox(x)) != x at "
        f"{[i for i in range(256) if rev_bytes[i] != inputs[i]][:8]}"
    )
