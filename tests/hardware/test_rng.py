"""Hardware-RNG entropy properties on the Adafruit ESP32-C6 Feather.

The TARGET=c6 build of `rng_bytes` reads the on-chip LPPERI hardware RNG
(0x600B2808) instead of the qemu-virt deterministic-fake CSPRNG. The
output is not predictable from software, so we cannot KAT it — we test
shape properties instead:

* Multiple calls produce different output (the PRNG is not stuck on one
  state).
* No call's output is all-zero or all-0xff (which would indicate the
  peripheral is mis-clocked or the load address is reading flash padding
  instead of the RNG register).
* Cross-byte distribution: in a 256-byte sample, the number of distinct
  byte values is >32 (roughly 12.5% — generous floor, real entropy
  produces >200 distinct on average).

Without WiFi/BLE the C6 RNG is hardware-seeded but not continuously
reseeded by the analog noise source, so quality is below cryptographic
grade. The production HMAC-DRBG (NIST SP 800-90A) seeded by this raw
RNG lands later. This test only certifies that the raw-RNG plumbing
works on real silicon, replacing the deterministic-fake.

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


def _draw(t: target.HwTarget, count: int) -> bytes:
    """Trigger the 'r' KAT (rng_init + rng_bytes) and parse the emitted hex."""
    assert 1 <= count <= 255, "frame layout encodes count in a single byte"
    framed = oracle.kiss_encode(b"r" + bytes([count]))
    t.write(framed)
    lines = t.read_lines(timeout=3.0)
    events = log_parser.parse_lines(line + "\r\n" for line in lines)
    evt = log_parser.find_event(events, module="rng", event="bytes")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == count, (len(out), count)
    return out


def test_rng_two_calls_differ(hw: target.HwTarget) -> None:
    """Successive calls must not produce identical output (the chip's
    RNG would have to be stuck on a single state for this to fail)."""
    a = _draw(hw, 32)
    b = _draw(hw, 32)
    assert a != b, f"identical RNG output across two calls: {a.hex()}"


def test_rng_not_all_zero_or_ones(hw: target.HwTarget) -> None:
    """All-zero or all-0xff output suggests we are reading something
    other than the LPPERI register (e.g., flash padding or a deasserted
    bus). Real RNG output essentially never hits these patterns."""
    sample = _draw(hw, 64)
    assert sample != b"\x00" * 64, "RNG returned all zero"
    assert sample != b"\xff" * 64, "RNG returned all 0xff"


def test_rng_byte_distribution(hw: target.HwTarget) -> None:
    """Loose distribution check: a 255-byte sample (the largest the
    frame layout permits) should hit at least 32 distinct byte values.

    A truly stuck or strongly-biased source (everything 0x00, repeating
    pattern, single-byte cycle) would fail this. Random uniform bytes
    average ~225 distinct values out of 255 draws by the birthday
    formula, so 32 is a generous floor that won't false-positive even
    if the C6 PRNG is degraded without WiFi/BLE seeding."""
    sample = _draw(hw, 255)
    distinct = len(set(sample))
    assert distinct > 32, (
        f"only {distinct} distinct byte values in 255-byte RNG sample; "
        f"sample={sample.hex()}"
    )
