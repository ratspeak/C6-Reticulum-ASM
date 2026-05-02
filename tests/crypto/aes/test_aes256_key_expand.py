"""KAT for aes256_key_expand against FIPS 197 §A.3.

Sends the 32-byte master key under the 'K' marker; expects the full
240-byte schedule back as 480 hex chars.

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


# FIPS 197 Appendix A.3 input key.
KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
assert len(KEY) == 32

# FIPS 197 Appendix A.3 expanded key — 60 words = 240 bytes.
EXPECTED = bytes.fromhex(
    # round 0
    "603deb1015ca71be2b73aef0857d7781"
    # round 1
    "1f352c073b6108d72d9810a30914dff4"
    # round 2
    "9ba354118e6925afa51a8b5f2067fcde"
    # round 3
    "a8b09c1a93d194cdbe49846eb75d5b9a"
    # round 4
    "d59aecb85bf3c917fee94248de8ebe96"
    # round 5
    "b5a9328a2678a64798312229 2f6c79b3".replace(" ", "")
    +
    # round 6
    "812c81addadf48ba24360af2fab8b464"
    # round 7
    "98c5bfc9bebd198e268c3ba709e04214"
    # round 8
    "68007bacb2df331696e939e46c518d80"
    # round 9
    "c814e20476a9fb8a5025c02d59c58239"
    # round 10
    "de1369676ccc5a71fa256395 9674ee15".replace(" ", "")
    +
    # round 11
    "5886ca5d2e2f31d77e0af1fa27cf73c3"
    # round 12
    "749c47ab18501ddae2757e4f7401905a"
    # round 13
    "cafaaae3e4d59b349adf6acebd10190d"
    # round 14
    "fe4890d1e6188d0b046df344706c631e"
)
assert len(EXPECTED) == 240


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static ----------

def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes256_key_expand") > 0


def test_calls_aes_subword(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf,
                                     symbol="aes256_key_expand")
    assert "aes_subword" in body, body


# ---------- KAT ----------

def _run(elf, frame: bytes, *, timeout: float = 8.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def test_fips197_a3_vector(artifacts: build.BuildArtifacts) -> None:
    payload = b"K" + KEY
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="aes", event="key_expand")
    assert evt is not None, [e.raw for e in events]
    got_hex = evt.fields.get("hex", "")
    assert len(got_hex) == 480, (
        f"expected 480 hex chars (240 bytes), got {len(got_hex)}"
    )
    got = bytes.fromhex(got_hex)
    diffs = [(i, got[i], EXPECTED[i]) for i in range(240)
             if got[i] != EXPECTED[i]]
    assert not diffs, (
        f"key schedule mismatch at {len(diffs)} of 240 bytes; first: "
        + ", ".join(f"@{i}: got={g:02x} want={w:02x}"
                    for i, g, w in diffs[:10])
    )
