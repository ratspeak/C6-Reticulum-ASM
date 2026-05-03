"""KAT for x25519_keypair executed under QEMU.

Frame: 'k' (no args). The dispatcher resets the deterministic-fake RNG,
then calls x25519_keypair, which:
  1. Fills sk_out (kiss_buf) with 32 bytes from rng_bytes.
  2. Computes pk_out (x25519_field_buf) = X25519(sk_out, base=9).
The handler emits two log lines: keypair_sk and keypair_pk.

This test:
  - Computes the expected sk by replaying the RNG oracle in Python.
  - Computes the expected pk via pyca/cryptography's X25519.
  - Asserts both match the asm output byte-for-byte.
"""
from __future__ import annotations

import re
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

from harness import build, drbg_oracle, log_parser, oracle, target


def _expected_sk() -> bytes:
    """First 32 bytes of `rng_bytes` after a fresh `rng_init`. The
    HMAC-DRBG-SHA-256 oracle (drbg_oracle.drbg_oracle) mirrors the
    asm pipeline: instantiate from 48 bytes of deterministic-fake
    entropy, then generate 32 bytes."""
    return drbg_oracle.drbg_oracle(32)


def _expected_pk(sk: bytes) -> bytes:
    """X25519(sk, base=9) via pyca/cryptography."""
    pk_obj = X25519PrivateKey.from_private_bytes(sk).public_key()
    return pk_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_keypair") > 0


def test_calls_rng_and_scalar_mult(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_keypair")
    assert "rng_bytes" in body, "rng_bytes not invoked"
    assert "x25519_scalar_mult" in body, "x25519_scalar_mult not invoked"


def test_references_base_point(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_keypair")
    assert "x25519_base_point" in body, "base point constant not referenced"


def test_no_data_dependent_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_keypair")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_keypair")
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


def _qemu_keypair(artifacts) -> tuple[bytes, bytes]:
    payload = b"k"
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    sk_evt = log_parser.find_event(events, module="x25519", event="keypair_sk")
    pk_evt = log_parser.find_event(events, module="x25519", event="keypair_pk")
    assert sk_evt is not None, [e.raw for e in events]
    assert pk_evt is not None, [e.raw for e in events]
    sk = bytes.fromhex(sk_evt.fields["hex"])
    pk = bytes.fromhex(pk_evt.fields["hex"])
    assert len(sk) == 32 and len(pk) == 32
    return sk, pk


def test_keypair_matches_oracle(artifacts):
    """sk = first RNG block after rng_init; pk = X25519(sk, 9)."""
    sk, pk = _qemu_keypair(artifacts)
    expected_sk = _expected_sk()
    expected_pk = _expected_pk(expected_sk)
    assert sk == expected_sk, (
        f"\n  sk got:  {sk.hex()}\n  sk want: {expected_sk.hex()}"
    )
    assert pk == expected_pk, (
        f"\n  pk got:  {pk.hex()}\n  pk want: {expected_pk.hex()}"
    )


def test_keypair_deterministic(artifacts):
    """Two boots with rng_init produce identical (sk, pk) pairs."""
    a = _qemu_keypair(artifacts)
    b = _qemu_keypair(artifacts)
    assert a == b
