"""End-to-end KAT for the SHA-256 chain (init → update → final).

Sends a KISS-framed payload starting with the byte `'S'` (0x53) — the
sha256-test marker — to qemu over its stdin. `_main` runs sha256 on
the payload bytes (after the marker) and emits a structured log line
with the digest. The host parses the line and compares against the
FIPS 180-4 §B test vectors.

This test exercises every line of every milestone-2 sha256_* function
written so far: init, compress (twice for the two-block case), update
(both buffered and whole-block paths), and final (both single-trailing
and double-trailing block paths).

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import time

import pytest

from harness import build, log_parser, oracle, target

# FIPS 180-4 Appendix B test vectors (SHA-256 of well-known inputs).
KAT = (
    # FIPS B.1 — single-block message
    (b"abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    # FIPS B.2 — two-block message
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    # Empty message (FIPS B trailing case)
    (b"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _run_with_input(elf, stdin_bytes: bytes, *, gap_s: float = 0.05,
                    timeout: float = 2.5) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        if gap_s > 0:
            time.sleep(gap_s)
        if stdin_bytes:
            t.write(stdin_bytes)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


@pytest.mark.parametrize("payload,expected_hex", KAT)
def test_sha256_kat(
    artifacts: build.BuildArtifacts, payload: bytes, expected_hex: str,
) -> None:
    """Send `'S' + payload` as a KISS frame; expect digest(payload) in log."""
    framed = oracle.kiss_encode(b"S" + payload)
    events = _run_with_input(artifacts.elf, framed)

    sha = log_parser.find_event(events, module="sha256", event="digest")
    assert sha is not None, \
        f"no sha256.digest event for {payload!r}: {[e.raw for e in events]}"
    got = sha.fields.get("hex")
    assert got == expected_hex, \
        f"digest mismatch for {payload!r}: got {got}, want {expected_hex}"
