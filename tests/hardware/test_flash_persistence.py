"""TARGET_C6 flash persistence contract tests.

These tests are hardware-marked because they erase the reserved identity
sector on the physical Adafruit ESP32-C6 Feather, then prove the boot
load-or-create announce path survives a reset without reflashing.
"""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest

from harness import build, log_parser, oracle, target

pytestmark = pytest.mark.hardware

FLASH_CHIP_SIZE = 0x0040_0000
FLASH_IDENTITY_ABS_OFFSET = 0x003F_F000
FLASH_IDENTITY_REGION_SIZE = 0x1000
FLASH_SECTOR_SIZE = 0x1000
FLASH_PAGE_SIZE = 0x100
ESP_BAUD = 460800


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("c6")


def test_flash_contract_constants_are_aligned() -> None:
    assert FLASH_IDENTITY_ABS_OFFSET + FLASH_IDENTITY_REGION_SIZE == FLASH_CHIP_SIZE
    assert FLASH_IDENTITY_ABS_OFFSET % FLASH_SECTOR_SIZE == 0
    assert FLASH_IDENTITY_REGION_SIZE == FLASH_SECTOR_SIZE
    assert FLASH_SECTOR_SIZE % FLASH_PAGE_SIZE == 0


def _config(
    artifacts: build.BuildArtifacts, port: str, *, auto_flash: bool,
) -> target.TargetConfig:
    return target.TargetConfig(
        binary=artifacts.elf,
        image_bin=artifacts.image_bin,
        serial_port=port,
        auto_flash=auto_flash,
    )


def _start_hw(cfg: target.TargetConfig) -> target.HwTarget:
    hw = target.HwTarget(cfg)
    if not hw.is_available():
        pytest.skip("HwTarget unavailable (missing esptool/pyserial/port)")
    hw.start()
    return hw


def _erase_identity_sector(port: str) -> None:
    esptool = shutil.which("esptool.py") or shutil.which("esptool")
    if esptool is None:
        pytest.skip("esptool not available")
    cmd = [
        esptool,
        "--chip", "esp32c6",
        "--port", port,
        "--baud", str(ESP_BAUD),
        "erase_region",
        hex(FLASH_IDENTITY_ABS_OFFSET),
        hex(FLASH_SECTOR_SIZE),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"{' '.join(cmd)} failed with exit {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )


def _kiss_frames_from_output(out: bytes) -> list[bytes]:
    frames: list[bytes] = []
    pos = 0
    fend = bytes([oracle.KISS_FEND])
    while True:
        start = out.find(fend, pos)
        if start < 0:
            return frames
        end = out.find(fend, start + 1)
        if end < 0:
            return frames
        frames.append(out[start:end + 1])
        pos = end + 1


def _send_announce_until_frame(
    hw: target.HwTarget, payload: bytes, *, timeout: float = 30.0,
) -> tuple[list[log_parser.LogEvent], bytes, bytes]:
    hw.write(oracle.kiss_encode(payload))
    deadline = time.monotonic() + timeout
    out = bytearray()
    frames: list[bytes] = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        chunk = hw.read(4096, min(remaining, 0.2))
        if chunk:
            out.extend(chunk)
            frames = _kiss_frames_from_output(bytes(out))
            if frames:
                break

    assert frames, bytes(out)
    decoded = oracle.kiss_decode(frames[0])
    assert len(decoded) == 1, frames[0]

    first_frame = bytes(out).find(frames[0])
    log_prefix = bytes(out[:first_frame]).decode("utf-8", errors="replace")
    events = log_parser.parse_lines(
        line + "\r\n" for line in log_prefix.splitlines() if line
    )
    return events, decoded[0], bytes(out)


def test_identity_reset_retention_on_hardware(
    request: pytest.FixtureRequest, artifacts: build.BuildArtifacts,
) -> None:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    port = request.config.getoption("--hardware-port")

    # First flash the current image. The sector erase happens after flashing so
    # this test proves identity creation from a known-erased persistence slot.
    hw = _start_hw(_config(artifacts, port, auto_flash=True))
    hw.stop()
    _erase_identity_sector(port)

    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    app_data = b"m4-reset-retention"
    command = b"N" + name_hash + app_data

    hw = _start_hw(_config(artifacts, port, auto_flash=False))
    try:
        first_events, first_raw, first_out = _send_announce_until_frame(hw, command)
    finally:
        hw.stop()

    assert log_parser.find_event(
        first_events, module="identity", event="created"
    ), [e.raw for e in first_events] or first_out
    assert oracle.announce_validate_pyca(first_raw)
    first = oracle.announce_parse(first_raw)
    first_identity_hash = oracle.identity_hash(first.public_key)

    hw = _start_hw(_config(artifacts, port, auto_flash=False))
    try:
        second_events, second_raw, second_out = _send_announce_until_frame(hw, command)
    finally:
        hw.stop()

    assert log_parser.find_event(
        second_events, module="identity", event="loaded"
    ), [e.raw for e in second_events] or second_out
    assert oracle.announce_validate_pyca(second_raw)
    second = oracle.announce_parse(second_raw)
    assert second.public_key == first.public_key
    assert oracle.identity_hash(second.public_key) == first_identity_hash
    assert second.destination_hash == first.destination_hash
