"""KAT for aes256_cbc_encrypt + aes256_cbc_decrypt.

Vectors from NIST SP 800-38A §F.2.5 (encrypt) and §F.2.6 (decrypt) —
identical key/IV/4-block plaintext, just running the chain in opposite
directions. Plus a round-trip across an arbitrary 3-block payload.
"""

from __future__ import annotations

import time

import pytest

from harness import build, log_parser, oracle, target


# NIST SP 800-38A §F.2 (AES-256-CBC).
KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CIPHERTEXT = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)
assert len(PLAINTEXT) == 64 == len(CIPHERTEXT)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static ----------

def test_cbc_encrypt_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes256_cbc_encrypt") > 0


def test_cbc_decrypt_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes256_cbc_decrypt") > 0


def test_cbc_encrypt_calls_block_encrypt(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="aes256_cbc_encrypt")
    assert "aes256_encrypt_block" in body, body


def test_cbc_decrypt_calls_block_decrypt(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="aes256_cbc_decrypt")
    assert "aes256_decrypt_block" in body, body


# ---------- KAT ----------

def _run(elf, frame: bytes, *, timeout: float = 12.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _cbc_encrypt(artifacts, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    assert len(key) == 32 and len(iv) == 16 and len(plaintext) % 16 == 0
    nblocks = len(plaintext) // 16
    assert 0 <= nblocks <= 0xFF
    payload = b"V" + key + iv + bytes([nblocks]) + plaintext
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="aes", event="cbc_encrypt")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == len(plaintext)
    return out


def _cbc_decrypt(artifacts, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 32 and len(iv) == 16 and len(ciphertext) % 16 == 0
    nblocks = len(ciphertext) // 16
    assert 0 <= nblocks <= 0xFF
    payload = b"v" + key + iv + bytes([nblocks]) + ciphertext
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="aes", event="cbc_decrypt")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == len(ciphertext)
    return out


def test_nist_38a_f25_encrypt(artifacts: build.BuildArtifacts) -> None:
    got = _cbc_encrypt(artifacts, KEY, IV, PLAINTEXT)
    assert got == CIPHERTEXT, (
        f"\ngot:  {got.hex()}\nwant: {CIPHERTEXT.hex()}"
    )


def test_nist_38a_f26_decrypt(artifacts: build.BuildArtifacts) -> None:
    got = _cbc_decrypt(artifacts, KEY, IV, CIPHERTEXT)
    assert got == PLAINTEXT, (
        f"\ngot:  {got.hex()}\nwant: {PLAINTEXT.hex()}"
    )


def test_round_trip_3_blocks(artifacts: build.BuildArtifacts) -> None:
    """Independent payload, encrypt then decrypt; expect identity."""
    key = bytes(range(32))
    iv = bytes.fromhex("0123456789abcdef0011223344556677")
    pt = bytes(range(48))
    ct = _cbc_encrypt(artifacts, key, iv, pt)
    rt = _cbc_decrypt(artifacts, key, iv, ct)
    assert rt == pt, f"round trip mismatch:\ngot:  {rt.hex()}\nwant: {pt.hex()}"


def test_single_block(artifacts: build.BuildArtifacts) -> None:
    """Single-block CBC = single-block encryption with IV pre-XOR."""
    pt = b"\x00" * 16
    ct = _cbc_encrypt(artifacts, KEY, IV, pt)
    rt = _cbc_decrypt(artifacts, KEY, IV, ct)
    assert rt == pt
