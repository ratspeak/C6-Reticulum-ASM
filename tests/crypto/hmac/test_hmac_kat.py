"""End-to-end KAT for HMAC-SHA-256 against RFC 4231 vectors.

The 'H' marker path in `_main` runs hmac_sha256 over a key+message
embedded in the KISS frame. Frame layout:

    'H' || keylen[1] || key[keylen] || msg[*]

Output: a `hmac.tag` log event with `hex=<64hex>`.

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import time

import pytest

from harness import build, log_parser, oracle, target

# RFC 4231 §4.2 — Test Case 1 (20-byte key of 0x0b, "Hi There" message).
RFC4231_TC1 = (
    bytes([0x0B] * 20),
    b"Hi There",
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
)
# RFC 4231 §4.3 — TC2 (key "Jefe", message "what do ya want for nothing?").
RFC4231_TC2 = (
    b"Jefe",
    b"what do ya want for nothing?",
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
)
# RFC 4231 §4.4 — TC3 (20 bytes 0xaa key, 50 bytes 0xdd msg).
RFC4231_TC3 = (
    bytes([0xAA] * 20),
    bytes([0xDD] * 50),
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
)
# RFC 4231 §4.7 — TC6 (131-byte key triggers the long-key SHA-256 path).
RFC4231_TC6 = (
    bytes([0xAA] * 131),
    b"Test Using Larger Than Block-Size Key - Hash Key First",
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
)

CASES = [
    pytest.param(*RFC4231_TC1, id="rfc4231-tc1"),
    pytest.param(*RFC4231_TC2, id="rfc4231-tc2"),
    pytest.param(*RFC4231_TC3, id="rfc4231-tc3"),
    pytest.param(*RFC4231_TC6, id="rfc4231-tc6-longkey"),
]


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _run(elf, frame: bytes, *, timeout: float = 2.5) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


@pytest.mark.parametrize("key,msg,expected", CASES)
def test_hmac_kat(
    artifacts: build.BuildArtifacts, key: bytes, msg: bytes, expected: str,
) -> None:
    assert len(key) <= 0xFF, "test harness limits key length to 1 byte"
    payload = b"H" + bytes([len(key)]) + key + msg
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)

    h = log_parser.find_event(events, module="hmac", event="tag")
    assert h is not None, \
        f"no hmac.tag event for key={key.hex()} msg={msg!r}: {[e.raw for e in events]}"
    got = h.fields.get("hex")
    assert got == expected, \
        f"HMAC mismatch: got {got}, want {expected}"
