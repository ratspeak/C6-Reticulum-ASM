"""SX1262 LoRa hardware smoke tests for milestone 8.

These tests require the Wio-SX1262 module wired per docs/hardware/lora.md.
They assert that the boot-time reset/init path reaches STBY_RC and that the
SX1262 GetStatus readback is not just an all-zero/no-radio SPI response.
"""

from __future__ import annotations

import pytest

from harness import build, log_parser, target

pytestmark = pytest.mark.hardware

SX1262_STATUS_CHIP_MODE_MASK = 0x70
SX1262_STATUS_STBY_RC = 0x20
LORA_ERR_BUSY_TIMEOUT_HEX = "fffffffe"


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
