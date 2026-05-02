"""KAT for aes256_decrypt_block — FIPS 197 §C.3 reverse + round trip."""

from __future__ import annotations

import time

import pytest

from harness import build, log_parser, oracle, target


# FIPS 197 §C.3 (decrypt direction).
KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
CIPHERTEXT = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")

# Independent vector: AES-256 decrypt of dc95...2087 with all-zero key.
KEY2 = bytes(32)
CIPHERTEXT2 = bytes.fromhex("dc95c078a2408989ad48a21492842087")
PLAINTEXT2 = bytes(16)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes256_decrypt_block") > 0


def test_calls_inverse_chain(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="aes256_decrypt_block")
    for sym in ("aes_invsubbytes", "aes_invshiftrows", "aes_invmixcolumns",
                "aes_addroundkey"):
        assert sym in body, f"{sym} not referenced from decrypt_block"


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


def _decrypt(artifacts, key: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 32 and len(ciphertext) == 16
    payload = b"D" + key + ciphertext
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="aes", event="decrypt")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 16
    return out


def test_fips197_c3_reverse(artifacts: build.BuildArtifacts) -> None:
    got = _decrypt(artifacts, KEY, CIPHERTEXT)
    assert got == PLAINTEXT, (
        f"\ngot:  {got.hex()}\nwant: {PLAINTEXT.hex()}"
    )


def test_zero_vector_reverse(artifacts: build.BuildArtifacts) -> None:
    got = _decrypt(artifacts, KEY2, CIPHERTEXT2)
    assert got == PLAINTEXT2, (
        f"\ngot:  {got.hex()}\nwant: {PLAINTEXT2.hex()}"
    )
