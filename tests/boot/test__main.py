"""Integration test for src/boot/_main.S.

Boots the firmware in qemu via EmuTarget, reads UART output, asserts
the banner emitted by _main appears in well-formed log-line shape.

This is the end-to-end check for the bring-up chain assembled in
milestone 1: _reset → _init_bss → _init_data → clock_init → uart_init →
uart_tx_bytes → observable bytes on UART. If any link breaks, this
test fails.
"""

from __future__ import annotations

import pytest

from harness import build, log_parser, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_emits_boot_banner(artifacts: build.BuildArtifacts) -> None:
    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    with t:
        lines = t.read_lines(timeout=2.0)

    banner = next(
        (line for line in lines if "boot" in line and "ready" in line), None
    )
    assert banner is not None, f"banner not found; got: {lines!r}"

    ev = log_parser.parse_line(banner + "\r\n")
    assert ev is not None, f"banner did not parse as a log line: {banner!r}"
    assert ev.module == "boot"
    assert ev.event == "ready"


def test_banner_has_canonical_timestamp_field(
    artifacts: build.BuildArtifacts,
) -> None:
    """The boot banner's timestamp field is the 8-hex-digit format per
    ADR-0008 — a real `clock_now_ms` reading at the moment `log_event`
    runs for `boot.ready`. The exact value is implementation-detail
    (it depends on how much work happens between `clock_init` and the
    log call — including the HMAC-DRBG instantiate inside `rng_init`),
    so we assert format only: 8 lowercase hex digits, parseable, and
    ≤ a generous upper bound that any plausible boot path stays under."""
    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    with t:
        lines = t.read_lines(timeout=2.0)

    banner = next(
        (line for line in lines if "boot" in line and "ready" in line), None
    )
    assert banner is not None
    ev = log_parser.parse_line(banner + "\r\n")
    assert ev is not None
    assert len(ev.ts_raw) == 8 and all(c in "0123456789abcdef" for c in ev.ts_raw)
    assert ev.ts_ms < 100, f"boot to ready took {ev.ts_ms} ms — investigate"
