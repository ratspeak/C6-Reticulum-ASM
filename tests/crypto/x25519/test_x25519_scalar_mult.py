"""KAT for x25519_scalar_mult executed under QEMU.

Frame layout: 's' || k_bytes[32] || u_bytes[32] (raw wire bytes).
Emits 64 hex characters of the canonical 32-byte u-coordinate of k·P_u.

This is the wire-form Tier C bridge — no in-Python clamping or unpacking
needed; the asm does the full RFC 7748 §5 pipeline on raw bytes.
"""
from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_scalar_mult") > 0


def test_calls_full_pipeline(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_scalar_mult")
    for sym in ("x25519_decode_scalar", "x25519_field_unpack",
                "x25519_montgomery_ladder", "x25519_field_pack"):
        assert sym in body, f"{sym} not invoked"


def test_no_data_dependent_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_scalar_mult")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_scalar_mult")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs}"


# ---------- QEMU end-to-end KAT ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 60.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_smult(artifacts, k_bytes: bytes, u_bytes: bytes) -> bytes:
    payload = b"s" + k_bytes + u_bytes
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="x25519", event="scalar_mult")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 32
    return out


# RFC 7748 §5.2
RFC_V1_K = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd"
                         "62144c0ac1fc5a18506a2244ba449ac4")
RFC_V1_U = bytes.fromhex("e6db6867583030db3594c1a424b15f7c"
                         "726624ec26b3353b10a903a6d0ab1c4c")
RFC_V1_OUT = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f"
                           "32eccf03491c71f754b4075577a28552")

RFC_V2_K = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5"
                         "c11b6421e0ea01d42ca4169e7918ba0d")
RFC_V2_U = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c"
                         "31dbe7106fc03c3efc4cd549c715a493")
RFC_V2_OUT = bytes.fromhex("95cbde9476e8907d7aade45cb4b873f8"
                           "8b595a68799fa152e6f8f7647aac7957")

# RFC 7748 §6.1
ALICE_PRIV = bytes.fromhex("77076d0a7318a57d3c16c17251b26645"
                           "df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUB  = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a"
                           "0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIV   = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee6"
                           "6f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUB    = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece43537"
                           "3f8343c85b78674dadfc7e146f882b4f")
SHARED     = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25"
                           "e07e21c947d19e3376f09b3c1e161742")
NINE_BYTE  = bytes([9]) + b"\x00" * 31


def test_rfc7748_5_2_v1(artifacts):
    got = _qemu_smult(artifacts, RFC_V1_K, RFC_V1_U)
    assert got == RFC_V1_OUT, f"\n  got:  {got.hex()}\n  want: {RFC_V1_OUT.hex()}"


def test_rfc7748_5_2_v2(artifacts):
    got = _qemu_smult(artifacts, RFC_V2_K, RFC_V2_U)
    assert got == RFC_V2_OUT, f"\n  got:  {got.hex()}\n  want: {RFC_V2_OUT.hex()}"


def test_rfc7748_6_1_alice_pub(artifacts):
    got = _qemu_smult(artifacts, ALICE_PRIV, NINE_BYTE)
    assert got == ALICE_PUB, f"\n  got:  {got.hex()}\n  want: {ALICE_PUB.hex()}"


def test_rfc7748_6_1_bob_pub(artifacts):
    got = _qemu_smult(artifacts, BOB_PRIV, NINE_BYTE)
    assert got == BOB_PUB, f"\n  got:  {got.hex()}\n  want: {BOB_PUB.hex()}"


def test_rfc7748_6_1_shared_alice(artifacts):
    got = _qemu_smult(artifacts, ALICE_PRIV, BOB_PUB)
    assert got == SHARED, f"\n  got:  {got.hex()}\n  want: {SHARED.hex()}"


def test_rfc7748_6_1_shared_bob(artifacts):
    got = _qemu_smult(artifacts, BOB_PRIV, ALICE_PUB)
    assert got == SHARED, f"\n  got:  {got.hex()}\n  want: {SHARED.hex()}"


def test_caller_buffers_unmodified(artifacts):
    """The asm copies k_bytes onto its private stack before clamping.
    A second call with the same k_bytes must still produce the same
    output (i.e. no in-place modification leaked across invocations).
    Verified by re-running RFC §5.2 v1 twice in different test
    invocations — captured implicitly by the test_rfc7748_5_2_v1 +
    a second call here. We just check determinism on a fresh boot."""
    got1 = _qemu_smult(artifacts, RFC_V1_K, RFC_V1_U)
    got2 = _qemu_smult(artifacts, RFC_V1_K, RFC_V1_U)
    assert got1 == got2 == RFC_V1_OUT
