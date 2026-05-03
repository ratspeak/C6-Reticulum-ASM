"""Integration test for src/boot/_main.S.

Boots the firmware in qemu via EmuTarget, reads UART output, asserts
the banner emitted by _main appears in well-formed log-line shape.

This is the end-to-end check for the bring-up chain assembled in
milestone 1: _reset → _init_bss → _init_data → clock_init → uart_init →
uart_tx_bytes → observable bytes on UART. If any link breaks, this
test fails.
"""

from __future__ import annotations

import importlib.util

import pytest

from harness import build, drbg_oracle, log_parser, oracle, target


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


def _expected_identity_and_random() -> tuple[oracle.IdentityMaterial, bytes]:
    k, v = drbg_oracle.drbg_instantiate()
    x25519_sk, k, v = drbg_oracle.drbg_generate(k, v, 32)
    ed25519_seed, k, v = drbg_oracle.drbg_generate(k, v, 32)
    random_hash, _k, _v = drbg_oracle.drbg_generate(k, v, 10)
    return oracle.identity_from_private_parts(x25519_sk, ed25519_seed), random_hash


def test_announce_command_emits_valid_kiss_frame(
    artifacts: build.BuildArtifacts,
) -> None:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    app_data = b"main\xc0announce"
    command = oracle.kiss_encode(b"N" + name_hash + app_data)

    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with t:
        t.write(command)
        for _ in range(180):
            out.extend(t.read(4096, timeout=0.5))
            tx_idx = out.find(b"\tkiss\ttx_frame\tlen=")
            if tx_idx >= 0:
                first_fend = out.find(bytes([oracle.KISS_FEND]), tx_idx)
                if first_fend >= 0 and out.find(bytes([oracle.KISS_FEND]), first_fend + 1) >= 0:
                    break

    identity, random_hash = _expected_identity_and_random()
    expected = oracle.announce_build(identity, name_hash, random_hash, app_data)
    expected_kiss = oracle.kiss_encode(expected.raw_packet)

    first_fend = out.find(bytes([oracle.KISS_FEND]))
    assert first_fend >= 0, bytes(out)
    second_fend = out.find(bytes([oracle.KISS_FEND]), first_fend + 1)
    assert second_fend >= 0, bytes(out)
    frame = bytes(out[first_fend:second_fend + 1])
    log_text = bytes(out[:first_fend]).decode("utf-8", errors="replace")
    events = log_parser.parse_lines(line + "\r\n" for line in log_text.splitlines())

    assert log_parser.find_event(events, module="boot", event="ready")
    assert log_parser.find_event(events, module="kiss", event="rx_frame")
    assert log_parser.find_event(events, module="identity", event="ready")
    assert log_parser.find_event(
        events, module="announce", event="built", len=str(len(expected.raw_packet))
    )
    assert log_parser.find_event(
        events, module="kiss", event="tx_frame", len=str(len(expected_kiss))
    )
    assert frame == expected_kiss
    assert oracle.kiss_decode(frame) == [expected.raw_packet]
    assert oracle.announce_validate_pyca(expected.raw_packet)
    if importlib.util.find_spec("RNS") is not None:
        assert oracle.announce_validate_upstream(expected.raw_packet)
