"""KAT for ed25519_verify executed under QEMU.

Frame: 'y' || sig[64] || pk[32] || msg[*]. Emits 1 byte:
  0x00 = signature is valid
  0x01 = signature is invalid

Tests:
  - Round-trip: pyca-generated (sk, pk, msg, sig) → asm verify accepts.
  - Negative cases: tampered sig / pk / msg → asm verify rejects.
  - RFC 8032 §7.1 TEST 1 vector.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "ed25519_verify") > 0


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


def _qemu_verify(artifacts, sig: bytes, pk: bytes, msg: bytes) -> int:
    payload = b"y" + sig + pk + msg
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="ed25519", event="verify")
    assert evt is not None, [e.raw for e in events]
    raw = bytes.fromhex(evt.fields["hex"])
    assert len(raw) == 1
    return raw[0]


# Pre-derive (pk, sig) for a battery of seeds and messages.
def _derive(sk: bytes, msg: bytes) -> tuple[bytes, bytes]:
    sk_obj = Ed25519PrivateKey.from_private_bytes(sk)
    pk = sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = sk_obj.sign(msg)
    return pk, sig


_VALID_VECTORS = [
    ("rfc_test1", bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                                "4449c5697b326919703bac031cae7f60"), b""),
    ("short",     bytes(32),                     b"hello"),
    ("medium",    bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f"
                                "5b8a319f35aba624da8cf6ed4fb8a6fb"),
                                b"This is a test message of moderate length."),
    ("128byte",   bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1"
                                "66d38535076f094b85ce3a2e0b4458f7"),
                                b"\x55" * 128),
]


@pytest.mark.parametrize("name,sk,msg", _VALID_VECTORS,
                         ids=[v[0] for v in _VALID_VECTORS])
def test_valid_signature_accepted(artifacts, name, sk, msg):
    pk, sig = _derive(sk, msg)
    rc = _qemu_verify(artifacts, sig, pk, msg)
    assert rc == 0, f"{name}: expected accept (0), got {rc}"


def test_tampered_signature_rejected(artifacts):
    sk, msg = _VALID_VECTORS[1][1], _VALID_VECTORS[1][2]
    pk, sig = _derive(sk, msg)
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01                          # flip a bit in R
    rc = _qemu_verify(artifacts, bytes(bad_sig), pk, msg)
    assert rc == 1, f"expected reject (1), got {rc}"


def test_tampered_message_rejected(artifacts):
    sk, msg = _VALID_VECTORS[2][1], _VALID_VECTORS[2][2]
    pk, sig = _derive(sk, msg)
    rc = _qemu_verify(artifacts, sig, pk, msg + b"!")
    assert rc == 1, f"expected reject for tampered msg, got {rc}"


def test_wrong_pubkey_rejected(artifacts):
    sk, msg = _VALID_VECTORS[1][1], _VALID_VECTORS[1][2]
    pk, sig = _derive(sk, msg)
    wrong_sk = bytes((b + 1) & 0xFF for b in sk)
    wrong_pk, _ = _derive(wrong_sk, msg)
    rc = _qemu_verify(artifacts, sig, wrong_pk, msg)
    assert rc == 1, f"expected reject for wrong pk, got {rc}"
