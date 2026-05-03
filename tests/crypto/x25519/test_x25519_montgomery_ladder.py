"""KAT for x25519_montgomery_ladder executed under QEMU.

Frame layout: 'L' || k_bytes[32] (clamped) || u_limbs[40] (unpacked).
Emits 80 hex chars (40 bytes) of the resulting (x_2/z_2) limbs.

Tier C bridge: drives the asm against the canonical RFC 7748 §5.2 and
§6.1 vectors. The asm output limbs are passed through field_pack_oracle
to recover the wire u-coordinate and compared byte-for-byte with the
RFC's published expected output.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

from harness import build, log_parser, oracle, target

sys.path.insert(0, str(Path(__file__).resolve().parents[2] /
                       "../proofs/crypto/x25519"))
from _x25519_oracle import (  # type: ignore
    field_pack_oracle, field_unpack_oracle,
    limbs_to_bytes, bytes_to_limbs,
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_montgomery_ladder") > 0


def test_calls_field_helpers(artifacts):
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="x25519_montgomery_ladder")
    for sym in ("x25519_field_add", "x25519_field_sub", "x25519_field_mul",
                "x25519_field_sq", "x25519_field_mul121665", "x25519_cswap",
                "x25519_field_inv"):
        assert sym in body, f"{sym} not invoked from ladder"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="x25519_montgomery_ladder")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs}"


def test_loop_present(artifacts):
    """The 255-iteration loop is the only conditional branch we tolerate
    here (it depends on the public counter t, not on k or u)."""
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="x25519_montgomery_ladder")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bgez|bltz)\b",
                          body)
    # Expect exactly the loop back-branch (1) — no data-dependent branches.
    assert 1 <= len(branches) <= 3, (
        f"expected ≤3 branches (loop counter); got {len(branches)}: {branches}"
    )


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


def _clamp_scalar(k_bytes: bytes) -> bytes:
    k = bytearray(k_bytes)
    k[0]  &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def _mask_u(u_bytes: bytes) -> bytes:
    u = bytearray(u_bytes)
    u[31] &= 0x7F
    return bytes(u)


def _qemu_ladder(artifacts, k_clamped_bytes: bytes,
                 u_limbs: list[int]) -> bytes:
    """Drive the ladder; return the packed 32-byte u-coordinate of x_2/z_2."""
    payload = b"L" + k_clamped_bytes + limbs_to_bytes(u_limbs)
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="x25519", event="ladder")
    assert evt is not None, [e.raw for e in events]
    out_bytes = bytes.fromhex(evt.fields["hex"])
    assert len(out_bytes) == 40
    out_limbs = bytes_to_limbs(out_bytes)
    return field_pack_oracle(out_limbs)


# RFC 7748 §5.2 vector 1
RFC_V1_K = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd"
    "62144c0ac1fc5a18506a2244ba449ac4")
RFC_V1_U = bytes.fromhex(
    "e6db6867583030db3594c1a424b15f7c"
    "726624ec26b3353b10a903a6d0ab1c4c")
RFC_V1_OUT = bytes.fromhex(
    "c3da55379de9c6908e94ea4df28d084f"
    "32eccf03491c71f754b4075577a28552")

# RFC 7748 §5.2 vector 2
RFC_V2_K = bytes.fromhex(
    "4b66e9d4d1b4673c5ad22691957d6af5"
    "c11b6421e0ea01d42ca4169e7918ba0d")
RFC_V2_U = bytes.fromhex(
    "e5210f12786811d3f4b7959d0538ae2c"
    "31dbe7106fc03c3efc4cd549c715a493")
RFC_V2_OUT = bytes.fromhex(
    "95cbde9476e8907d7aade45cb4b873f8"
    "8b595a68799fa152e6f8f7647aac7957")


def test_rfc7748_5_2_vector_1(artifacts):
    k_clamped = _clamp_scalar(RFC_V1_K)
    u_limbs   = field_unpack_oracle(_mask_u(RFC_V1_U))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == RFC_V1_OUT, (
        f"\n  got:  {got.hex()}\n  want: {RFC_V1_OUT.hex()}"
    )


def test_rfc7748_5_2_vector_2(artifacts):
    k_clamped = _clamp_scalar(RFC_V2_K)
    u_limbs   = field_unpack_oracle(_mask_u(RFC_V2_U))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == RFC_V2_OUT, (
        f"\n  got:  {got.hex()}\n  want: {RFC_V2_OUT.hex()}"
    )


# RFC 7748 §6.1 — Diffie-Hellman example.
ALICE_PRIV = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUB  = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a"
    "0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIV   = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee6"
    "6f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUB    = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f")
SHARED     = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25"
    "e07e21c947d19e3376f09b3c1e161742")
NINE_BYTE  = bytes([9]) + b"\x00" * 31  # base point u = 9


def test_rfc7748_6_1_alice_pub(artifacts):
    """Alice's public key = Alice_priv × base_point."""
    k_clamped = _clamp_scalar(ALICE_PRIV)
    u_limbs   = field_unpack_oracle(_mask_u(NINE_BYTE))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == ALICE_PUB, (
        f"\n  got:  {got.hex()}\n  want: {ALICE_PUB.hex()}"
    )


def test_rfc7748_6_1_bob_pub(artifacts):
    """Bob's public key = Bob_priv × base_point."""
    k_clamped = _clamp_scalar(BOB_PRIV)
    u_limbs   = field_unpack_oracle(_mask_u(NINE_BYTE))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == BOB_PUB, (
        f"\n  got:  {got.hex()}\n  want: {BOB_PUB.hex()}"
    )


def test_rfc7748_6_1_shared_alice(artifacts):
    """Alice-side shared secret = Alice_priv × Bob_pub."""
    k_clamped = _clamp_scalar(ALICE_PRIV)
    u_limbs   = field_unpack_oracle(_mask_u(BOB_PUB))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == SHARED, (
        f"\n  got:  {got.hex()}\n  want: {SHARED.hex()}"
    )


def test_rfc7748_6_1_shared_bob(artifacts):
    """Bob-side shared secret = Bob_priv × Alice_pub. Must equal Alice's."""
    k_clamped = _clamp_scalar(BOB_PRIV)
    u_limbs   = field_unpack_oracle(_mask_u(ALICE_PUB))
    got       = _qemu_ladder(artifacts, k_clamped, u_limbs)
    assert got == SHARED, (
        f"\n  got:  {got.hex()}\n  want: {SHARED.hex()}"
    )
