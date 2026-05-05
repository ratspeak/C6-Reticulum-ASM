"""SX1262 LoRa hardware smoke tests for milestone 8.

These tests require the Wio-SX1262 V1.0 header carrier wired per
docs/hardware/lora.md.
They assert that the boot-time reset/init path reaches STBY_RC and that the
SX1262 GetStatus readback is not just an all-zero/no-radio SPI response.
"""

from __future__ import annotations

import pytest

from harness import build, log_parser, oracle, target

pytestmark = pytest.mark.hardware

SX1262_STATUS_CHIP_MODE_MASK = 0x70
SX1262_STATUS_STBY_RC = 0x20
LORA_ERR_BUSY_TIMEOUT_HEX = "fffffffe"
PATH_REQUEST_DEST_HASH = bytes.fromhex("6b9f66014d9853faab220fba47d02761")


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
        pytest.skip("HwTarget unavailable (missing esptool/pyserial/port)")
    t.start()
    yield t
    t.stop()


def _boot_events(hw: target.HwTarget) -> list[log_parser.LogEvent]:
    text = hw.boot_output.decode("utf-8", errors="replace")
    return log_parser.parse_lines(line + "\r\n" for line in text.splitlines() if line)


def test_sx1262_boot_reset_init_status_readback(hw: target.HwTarget) -> None:
    events = _boot_events(hw)
    init_error = log_parser.find_event(events, module="lora", event="init_error")
    assert init_error is None, (
        "SX1262 init failed before status readback; "
        f"{LORA_ERR_BUSY_TIMEOUT_HEX}=LORA_ERR_BUSY_TIMEOUT usually means BUSY "
        f"stayed high, missing radio power/ground, or BUSY pin wiring mismatch: "
        f"{[e.raw for e in events]}"
    )

    ready = log_parser.find_event(events, module="lora", event="ready")
    assert ready is not None, [e.raw for e in events]
    status_raw = ready.fields.get("status")
    assert status_raw is not None, ready.raw

    status = int(status_raw, 16)
    assert status != 0, ready.raw
    assert (status & SX1262_STATUS_CHIP_MODE_MASK) == SX1262_STATUS_STBY_RC, ready.raw


def test_sx1262_usb_triggered_tx_smoke(hw: target.HwTarget) -> None:
    requested = bytes(range(0x40, 0x50))
    tag = bytes(range(0xE0, 0xF0))
    raw_packet = bytes([0x08, 0x00]) + PATH_REQUEST_DEST_HASH + bytes([0x00]) + requested + tag

    hw.write(oracle.kiss_encode(b"T" + raw_packet))
    out = bytearray()
    events: list[log_parser.LogEvent] = []
    for _ in range(120):
        out.extend(hw.read(4096, timeout=0.25))
        text = bytes(out).decode("utf-8", errors="replace")
        events = log_parser.parse_lines(line + "\r\n" for line in text.splitlines())
        if log_parser.find_event(events, module="lora", event="tx_frame"):
            break
        if log_parser.find_event(events, module="lora", event="tx_error"):
            break

    tx = log_parser.find_event(events, module="lora", event="tx_frame")
    err = log_parser.find_event(events, module="lora", event="tx_error")
    assert err is None, [e.raw for e in events]
    assert tx is not None, bytes(out)
    assert int(tx.fields.get("len", "0"), 16) == len(raw_packet), tx.raw
