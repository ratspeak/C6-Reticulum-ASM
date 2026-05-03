"""Crypto KAT bridge on the physical Adafruit ESP32-C6 Feather.

Mirrors the qemu-virt tests under tests/crypto/ for the highest-distinct-
code-path primitives:

* SHA-512 — exercises the 64-bit (lo, hi) register-pair arithmetic the
  RV32IMAC core has to synthesize for a 64-bit hash.
* AES-256 single-block encrypt — exercises the Boyar-Peralta sbox plus
  GF(2^8) MixColumns; both are bit-twiddly and a likely place for any
  qemu-vs-real divergence to surface.
* X25519 scalar_mult — exercises the 10-limb radix-2^25.5 field arithmetic
  with the M extension's `mul`/`mulh` paired multiplies.
* Ed25519 sign + verify round-trip — composes SHA-512, scalarmult,
  point_compress, sc_reduce, and sc_muladd; passing this proves the
  whole signature scheme runs on real silicon.

Vectors come from FIPS 180-4 §C.1, FIPS 197 §C.3, RFC 7748 §5.2, and
RFC 8032 §7.1 — same sources the qemu-virt tests use, so a passing
hardware run is bit-for-bit equivalent to the qemu-virt run.

Skipped without --hardware. See tests/conftest.py for the opt-in.
"""

from __future__ import annotations

import pytest

from harness import build, log_parser, oracle, target

pytestmark = pytest.mark.hardware


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("c6")


@pytest.fixture
def hw(request: pytest.FixtureRequest, artifacts: build.BuildArtifacts) -> target.HwTarget:
    cfg = target.TargetConfig(
        binary=artifacts.elf,
        image_bin=artifacts.image_bin,
        serial_port=request.config.getoption("--hardware-port"),
    )
    t = target.HwTarget(cfg)
    if not t.is_available():
        pytest.skip("HwTarget unavailable")
    t.start()
    yield t
    t.stop()


def _send(t: target.HwTarget, payload: bytes, *, timeout: float = 4.0) -> list[log_parser.LogEvent]:
    """KISS-encode and send `payload`, then drain log lines.

    `timeout` is the per-test patience. Used for "fast" KATs where the
    chip emits all events within the first idle-pause; long-running
    operations (Ed25519 sign/verify, ~5-10 s on the C6 because the
    256-iteration scalar-mult loop is the dominant cost) should use
    `_send_until` instead.
    """
    framed = oracle.kiss_encode(payload)
    t.write(framed)
    lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _send_until(
    t: target.HwTarget, payload: bytes, *, module: str, event: str,
    timeout: float = 15.0,
) -> list[log_parser.LogEvent]:
    """Send `payload` and read until a `(module, event)` log line arrives
    or `timeout` elapses.

    The default Target.read_lines() returns on the first idle 50 ms gap
    after seeing any content. That works for fast KATs (compress+digest
    take well under one round-trip) but breaks for slow ones — Ed25519
    sign emits `kiss\\trx_frame` immediately, then spends ~5 s in
    scalar_mult before emitting the result. We need to keep draining
    until the result actually shows up.
    """
    import time
    framed = oracle.kiss_encode(payload)
    t.write(framed)
    deadline = time.monotonic() + timeout
    buf = bytearray()
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        chunk = t.read(4096, min(remaining, 0.2))
        if chunk:
            buf.extend(chunk)
            text = buf.decode("utf-8", errors="replace")
            events = log_parser.parse_lines(
                line + "\r\n" for line in text.splitlines() if line
            )
            if log_parser.find_event(events, module=module, event=event):
                return events
    text = buf.decode("utf-8", errors="replace")
    return log_parser.parse_lines(
        line + "\r\n" for line in text.splitlines() if line
    )


# ---- SHA-512 (FIPS 180-4 §C.1) ---------------------------------------------

SHA512_ABC = (
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
)


def test_sha512_abc_on_hardware(hw: target.HwTarget) -> None:
    events = _send(hw, b"habc")
    evt = log_parser.find_event(events, module="sha512", event="digest")
    assert evt is not None, [e.raw for e in events]
    assert evt.fields["hex"] == SHA512_ABC


# ---- AES-256 single-block encrypt (FIPS 197 §C.3) --------------------------

AES_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
AES_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
AES_CT = "8ea2b7ca516745bfeafc49904b496089"


def test_aes256_encrypt_block_on_hardware(hw: target.HwTarget) -> None:
    events = _send(hw, b"C" + AES_KEY + AES_PT)
    evt = log_parser.find_event(events, module="aes", event="encrypt")
    assert evt is not None, [e.raw for e in events]
    assert evt.fields["hex"] == AES_CT


# ---- X25519 scalar_mult (RFC 7748 §5.2 vector 1) ---------------------------

X25519_K = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
)
X25519_U = bytes.fromhex(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
)
X25519_OUT = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"


def test_x25519_scalar_mult_on_hardware(hw: target.HwTarget) -> None:
    events = _send(hw, b"s" + X25519_K + X25519_U)
    evt = log_parser.find_event(events, module="x25519", event="scalar_mult")
    assert evt is not None, [e.raw for e in events]
    assert evt.fields["hex"] == X25519_OUT


# ---- Ed25519 sign + verify (RFC 8032 §7.1 test 1) --------------------------

# RFC 8032 §7.1 test 1: empty message, deterministic signature.
ED25519_SK = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
ED25519_PK = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
ED25519_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_ed25519_sign_empty_on_hardware(hw: target.HwTarget) -> None:
    events = _send_until(hw, b"G" + ED25519_SK + b"",
                         module="ed25519", event="sign", timeout=20.0)
    evt = log_parser.find_event(events, module="ed25519", event="sign")
    assert evt is not None, [e.raw for e in events]
    assert evt.fields["hex"] == ED25519_SIG


def test_ed25519_verify_empty_on_hardware(hw: target.HwTarget) -> None:
    sig = bytes.fromhex(ED25519_SIG)
    events = _send_until(hw, b"y" + sig + ED25519_PK + b"",
                         module="ed25519", event="verify", timeout=20.0)
    evt = log_parser.find_event(events, module="ed25519", event="verify")
    assert evt is not None, [e.raw for e in events]
    # _main encodes the verify return code as a single hex byte.
    assert evt.fields["hex"] == "00", evt.raw  # 0x00 == valid


def test_ed25519_verify_rejects_tampered_signature_on_hardware(hw: target.HwTarget) -> None:
    """Negative round-trip: flip one bit of the signature; verify must
    return 0x01 (invalid). Catches accidental "always pass" regressions
    in hardware-side execution."""
    sig = bytearray(bytes.fromhex(ED25519_SIG))
    sig[0] ^= 0x01
    events = _send_until(hw, b"y" + bytes(sig) + ED25519_PK + b"",
                         module="ed25519", event="verify", timeout=20.0)
    evt = log_parser.find_event(events, module="ed25519", event="verify")
    assert evt is not None, [e.raw for e in events]
    assert evt.fields["hex"] == "01", evt.raw  # 0x01 == invalid
