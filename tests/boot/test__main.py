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


def _expected_identity_and_randoms(count: int) -> tuple[oracle.IdentityMaterial, list[bytes]]:
    k, v = drbg_oracle.drbg_instantiate()
    x25519_sk, k, v = drbg_oracle.drbg_generate(k, v, 32)
    ed25519_seed, k, v = drbg_oracle.drbg_generate(k, v, 32)
    random_hashes: list[bytes] = []
    for _ in range(count):
        random_hash, k, v = drbg_oracle.drbg_generate(k, v, 10)
        random_hashes.append(random_hash)
    return oracle.identity_from_private_parts(x25519_sk, ed25519_seed), random_hashes


def _expected_identity_and_random() -> tuple[oracle.IdentityMaterial, bytes]:
    identity, random_hashes = _expected_identity_and_randoms(1)
    return identity, random_hashes[0]


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
    assert log_parser.find_event(events, module="identity", event="created")
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


def test_second_announce_reuses_loaded_identity(
    artifacts: build.BuildArtifacts,
) -> None:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    first_app = b"first"
    second_app = b"second"
    command = (
        oracle.kiss_encode(b"N" + name_hash + first_app)
        + oracle.kiss_encode(b"N" + name_hash + second_app)
    )

    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with t:
        t.write(command)
        for _ in range(220):
            out.extend(t.read(4096, timeout=0.5))
            if len(_kiss_frames_from_output(bytes(out))) >= 2:
                break

    identity, random_hashes = _expected_identity_and_randoms(2)
    expected_first = oracle.announce_build(
        identity, name_hash, random_hashes[0], first_app
    )
    expected_second = oracle.announce_build(
        identity, name_hash, random_hashes[1], second_app
    )
    frames = _kiss_frames_from_output(bytes(out))
    assert len(frames) >= 2, bytes(out)
    assert frames[0] == oracle.kiss_encode(expected_first.raw_packet)
    assert frames[1] == oracle.kiss_encode(expected_second.raw_packet)
    assert b"\tidentity\tcreated" in out
    assert b"\tidentity\tloaded" in out
    assert oracle.kiss_decode(frames[0]) == [expected_first.raw_packet]
    assert oracle.kiss_decode(frames[1]) == [expected_second.raw_packet]


def _transport_announce_packet(app_data: bytes, random_seed: int, hops: int) -> bytes:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    identity = oracle.identity_from_private_parts(bytes(range(32)), bytes(range(32, 64)))
    name_hash = oracle.destination_name_hash_from_parts("rnstransport", "nodes")
    random_hash = bytes((random_seed + i) & 0xFF for i in range(10))
    raw = bytearray(oracle.announce_build(identity, name_hash, random_hash, app_data).raw_packet)
    raw[1] = hops & 0xFF
    return bytes(raw)


def _run_frames_until(
    artifacts: build.BuildArtifacts,
    frames: bytes,
    *,
    predicate,
    timeout_chunks: int = 240,
) -> tuple[list[log_parser.LogEvent], bytes]:
    cfg = target.TargetConfig(binary=artifacts.elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with t:
        t.write(frames)
        for _ in range(timeout_chunks):
            out.extend(t.read(4096, timeout=0.5))
            text = bytes(out).decode("utf-8", errors="replace")
            events = log_parser.parse_lines(line + "\r\n" for line in text.splitlines())
            if predicate(events):
                return events, bytes(out)

    text = bytes(out).decode("utf-8", errors="replace")
    return log_parser.parse_lines(line + "\r\n" for line in text.splitlines()), bytes(out)


def _assert_event_sequence(
    events: list[log_parser.LogEvent], sequence: list[tuple[str, str]]
) -> None:
    pos = -1
    for module, event in sequence:
        for idx in range(pos + 1, len(events)):
            if events[idx].module == module and events[idx].event == event:
                pos = idx
                break
        else:
            raise AssertionError((module, event, [e.raw for e in events]))


def test_inbound_valid_announce_updates_transport_path(
    artifacts: build.BuildArtifacts,
) -> None:
    raw = _transport_announce_packet(b"path", random_seed=0x10, hops=4)
    assert oracle.announce_validate_pyca(raw)

    events, out = _run_frames_until(
        artifacts,
        oracle.kiss_encode(raw),
        predicate=lambda evs: log_parser.find_event(
            evs, module="transport", event="path_updated"
        )
        is not None,
    )

    _assert_event_sequence(
        events,
        [
            ("kiss", "rx_frame"),
            ("packet", "parsed"),
            ("transport", "announce_valid"),
            ("transport", "path_updated"),
        ],
    )
    assert not log_parser.find_event(events, module="transport", event="announce_invalid"), out


def test_inbound_duplicate_announce_updates_existing_path(
    artifacts: build.BuildArtifacts,
) -> None:
    first = _transport_announce_packet(b"first-path", random_seed=0x20, hops=2)
    second = _transport_announce_packet(b"second-path", random_seed=0x30, hops=5)
    assert oracle.announce_parse(first).destination_hash == oracle.announce_parse(second).destination_hash

    events, out = _run_frames_until(
        artifacts,
        oracle.kiss_encode(first) + oracle.kiss_encode(second),
        predicate=lambda evs: len(
            log_parser.find_all(evs, module="transport", event="path_updated")
        )
        >= 2,
    )

    assert len(log_parser.find_all(events, module="transport", event="announce_valid")) >= 2, out
    assert len(log_parser.find_all(events, module="transport", event="path_updated")) >= 2, out
    assert not log_parser.find_event(events, module="transport", event="announce_invalid"), out


def test_inbound_invalid_announce_is_rejected_without_path_update(
    artifacts: build.BuildArtifacts,
) -> None:
    raw = bytearray(_transport_announce_packet(b"bad-path", random_seed=0x40, hops=1))
    raw[-1] ^= 0x01
    assert not oracle.announce_validate_pyca(bytes(raw))

    events, out = _run_frames_until(
        artifacts,
        oracle.kiss_encode(bytes(raw)),
        predicate=lambda evs: log_parser.find_event(
            evs, module="transport", event="announce_invalid"
        )
        is not None,
    )

    _assert_event_sequence(
        events,
        [
            ("kiss", "rx_frame"),
            ("packet", "parsed"),
            ("transport", "announce_invalid"),
        ],
    )
    assert not log_parser.find_event(events, module="transport", event="announce_valid"), out
    assert not log_parser.find_event(events, module="transport", event="path_updated"), out
