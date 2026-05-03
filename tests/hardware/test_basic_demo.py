"""End-to-end demo on the physical Adafruit ESP32-C6 Feather (ADR-0010).

These tests are the hardware mirror of the qemu-virt path exercised by
tests/packet/test_packet_parse_header.py and the SHA-256 KAT bridge in
tests/crypto/sha256/test_sha256_compress.py. They flash the firmware,
reset the chip, and assert the structured-log lines our `_main` emits
when fed (a) a well-formed Reticulum HEADER_1 packet, (b) a too-short
packet, and (c) the SHA-256 KAT trigger byte (`'S'` + `"abc"`).

Skipped by default. Run with `pytest --hardware tests/hardware/` to opt
in (or `RATSPEAK_HW=1`). Conftest plumbing lives in `tests/conftest.py`.
"""

from __future__ import annotations

import pytest

from harness import build, log_parser, oracle, target

pytestmark = pytest.mark.hardware


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    """Build TARGET=c6 once per module and reuse the .image.bin across tests."""
    return build.build("c6")


@pytest.fixture
def hw(request: pytest.FixtureRequest, artifacts: build.BuildArtifacts) -> target.HwTarget:
    """Open a fresh HwTarget per test. The class-level flash cache means
    the actual esptool reflash happens once per pytest session; reset +
    boot drain is per-test."""
    cfg = target.TargetConfig(
        binary=artifacts.elf,
        image_bin=artifacts.image_bin,
        serial_port=request.config.getoption("--hardware-port"),
    )
    t = target.HwTarget(cfg)
    if not t.is_available():
        pytest.skip("HwTarget unavailable (missing esptool/pyserial/port)")
    t.start()
    yield t
    t.stop()


def _send(t: target.HwTarget, payload: bytes) -> list[log_parser.LogEvent]:
    framed = oracle.kiss_encode(payload)
    t.write(framed)
    lines = t.read_lines(timeout=1.5)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _minimal_h1_packet(packet_type: int = 0x01) -> bytes:
    """A 19-byte HEADER_1 packet matching test_packet_parse_header.py."""
    flags = packet_type & 0x03
    return bytes([flags, 0x00]) + b"h" * 16 + bytes([0x00])


def test_minimum_h1_packet_is_parsed_on_hardware(hw: target.HwTarget) -> None:
    events = _send(hw, _minimal_h1_packet())
    assert log_parser.find_event(events, module="kiss", event="rx_frame")
    assert log_parser.find_event(events, module="packet", event="parsed"), \
        [e.raw for e in events]


def test_short_packet_is_rejected_on_hardware(hw: target.HwTarget) -> None:
    """Same payload as the qemu-virt sibling test — first byte is 0x01
    (not a KAT dispatcher tag) so the frame falls through to
    packet_parse_header where the short length triggers rejection."""
    events = _send(hw, b"\x01hrt!")
    assert log_parser.find_event(events, module="kiss", event="rx_frame")
    assert log_parser.find_event(events, module="packet", event="rejected"), \
        [e.raw for e in events]


def test_sha256_kat_on_hardware(hw: target.HwTarget) -> None:
    """SHA-256 KAT bridge: 'S' || 'abc' must produce FIPS 180-4 §B.1
    digest ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    on the wire. This proves the entire compress/update/final stack runs
    correctly on the real RV32IMAC core — bit-for-bit equivalent to the
    qemu-virt run and the Cryptol/SAW algorithmic spec."""
    events = _send(hw, b"Sabc")
    sha_event = log_parser.find_event(events, module="sha256", event="digest")
    assert sha_event is not None, [e.raw for e in events]
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha_event.fields.get("hex") == expected, sha_event.raw
