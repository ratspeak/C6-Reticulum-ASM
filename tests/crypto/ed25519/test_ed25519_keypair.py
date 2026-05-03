"""KAT for ed25519_keypair executed under QEMU.

Frame: 'g' (no args). Resets the deterministic-fake RNG, calls
ed25519_keypair, emits sk + pk on two log lines.

Verifies:
  - sk matches the first 32 bytes from rng_bytes after rng_init
    (HMAC-DRBG-SHA-256 instantiate + generate, see drbg_oracle).
  - pk matches pyca/cryptography's Ed25519PrivateKey.from_private_bytes(sk).
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)

from harness import build, drbg_oracle, log_parser, oracle, target


def _expected_sk() -> bytes:
    return drbg_oracle.drbg_oracle(32)


def _expected_pk(sk: bytes) -> bytes:
    pk = Ed25519PrivateKey.from_private_bytes(sk).public_key()
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "ed25519_keypair") > 0


def test_calls_pipeline(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="ed25519_keypair")
    for sym in ("rng_bytes", "sha512_init", "sha512_update", "sha512_final",
                "ed25519_scalarmult", "ed25519_point_compress",
                "ed25519_base_point"):
        assert sym in body, f"{sym} not invoked from ed25519_keypair"


def _run_frame(elf, frame: bytes, *, timeout: float = 120.0) -> list:
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
    payload = b"g"
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    sk_evt = log_parser.find_event(events, module="ed25519", event="keypair_sk")
    pk_evt = log_parser.find_event(events, module="ed25519", event="keypair_pk")
    assert sk_evt is not None, [e.raw for e in events]
    assert pk_evt is not None, [e.raw for e in events]
    sk = bytes.fromhex(sk_evt.fields["hex"])
    pk = bytes.fromhex(pk_evt.fields["hex"])
    assert len(sk) == 32 and len(pk) == 32
    return sk, pk


def test_keypair_matches_oracle(artifacts):
    sk, pk = _qemu_keypair(artifacts)
    expected_sk = _expected_sk()
    expected_pk = _expected_pk(expected_sk)
    assert sk == expected_sk, (
        f"\n  sk got:  {sk.hex()}\n  sk want: {expected_sk.hex()}"
    )
    assert pk == expected_pk, (
        f"\n  pk got:  {pk.hex()}\n  pk want: {expected_pk.hex()}"
    )
