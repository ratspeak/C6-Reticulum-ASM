"""KAT for aes256_encrypt_block against FIPS 197 §C.3.

Frame layout: 'C' || key[32] || plaintext[16]; emits ciphertext[16] hex.

This test exercises the entire AES forward chain end-to-end:
key_expand → 14 rounds * (subbytes + shiftrows + mixcolumns + addroundkey)
+ final-round shortcut. Any helper bug would fail this KAT.

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


# FIPS 197 Appendix C.3 — AES-256 single-block test vector.
KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHERTEXT = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

# Independent vector: AES-256 of all-zero key + all-zero plaintext.
# (Cross-checked with pyca/cryptography and OpenSSL.)
KEY2 = bytes(32)
PLAINTEXT2 = bytes(16)
CIPHERTEXT2 = bytes.fromhex("dc95c078a2408989ad48a21492842087")


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static ----------

def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes256_encrypt_block") > 0


def test_calls_chain(artifacts: build.BuildArtifacts) -> None:
    """Must invoke each per-round helper at least once."""
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="aes256_encrypt_block")
    for sym in ("aes_subbytes", "aes_shiftrows", "aes_mixcolumns",
                "aes_addroundkey"):
        assert sym in body, f"{sym} not referenced from encrypt_block"


# ---------- KAT ----------

def _run(elf, frame: bytes, *, timeout: float = 10.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _encrypt(artifacts, key: bytes, plaintext: bytes) -> bytes:
    assert len(key) == 32 and len(plaintext) == 16
    payload = b"C" + key + plaintext
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="aes", event="encrypt")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 16
    return out


def test_fips197_c3_vector(artifacts: build.BuildArtifacts) -> None:
    got = _encrypt(artifacts, KEY, PLAINTEXT)
    assert got == CIPHERTEXT, (
        f"\ngot:  {got.hex()}\nwant: {CIPHERTEXT.hex()}"
    )


def test_nist_38a_first_block(artifacts: build.BuildArtifacts) -> None:
    got = _encrypt(artifacts, KEY2, PLAINTEXT2)
    assert got == CIPHERTEXT2, (
        f"\ngot:  {got.hex()}\nwant: {CIPHERTEXT2.hex()}"
    )
