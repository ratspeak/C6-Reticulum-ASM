"""Tests for aes_mixcolumns + aes_invmixcolumns.

Static checks plus direct GF(2^8) KAT through the 'M' / 'm' markers in
_main. Test vectors per FIPS 197 §C.1 (round-1 cipher example) and
classical column-vector references widely used in AES test suites.

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target


# Classical per-column MixColumns vectors (e.g. FIPS 197 §C.1 round 1 +
# Wikipedia "Rijndael MixColumns").
#
# Each tuple: (input_4_bytes, expected_4_bytes_after_mixcolumns).
COLUMN_VECTORS = [
    ((0xdb, 0x13, 0x53, 0x45), (0x8e, 0x4d, 0xa1, 0xbc)),
    ((0xf2, 0x0a, 0x22, 0x5c), (0x9f, 0xdc, 0x58, 0x9d)),
    ((0x01, 0x01, 0x01, 0x01), (0x01, 0x01, 0x01, 0x01)),
    ((0xc6, 0xc6, 0xc6, 0xc6), (0xc6, 0xc6, 0xc6, 0xc6)),
    ((0xd4, 0xbf, 0x5d, 0x30), (0x04, 0x66, 0x81, 0xe5)),
    ((0x2d, 0x26, 0x31, 0x4c), (0x4d, 0x7e, 0xbd, 0xf8)),
]


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static ----------

def test_mixcolumns_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_mixcolumns") > 0


def test_invmixcolumns_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "aes_invmixcolumns") > 0


def test_mixcolumns_uses_xtime_constant(artifacts: build.BuildArtifacts) -> None:
    """The reducing polynomial byte 0x1B (=27) must appear as an immediate."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_mixcolumns")
    assert re.search(r"\bandi\b\s+\w+\s*,\s*\w+\s*,\s*(0x1b|27)\b", body), body


def test_invmixcolumns_uses_xtime_constant(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_invmixcolumns")
    assert re.search(r"\bandi\b\s+\w+\s*,\s*\w+\s*,\s*(0x1b|27)\b", body), body


def test_mixcolumns_no_data_branches(artifacts: build.BuildArtifacts) -> None:
    """The only branch in aes_mixcolumns is the column-loop bltu, which
    compares two pointers (not data)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="aes_mixcolumns")
    branches = re.findall(
        r"\b(beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bltz|bgtz)\b",
        body,
    )
    # exactly one bltu (the loop), no others
    assert branches.count("bltu") == 1, branches
    others = [b for b in branches if b != "bltu"]
    assert others == [], f"unexpected branches: {others}"


# ---------- KAT ----------

def _run(elf, frame: bytes, *, timeout: float = 3.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _run_mixcolumns(artifacts, state_in: bytes, *, marker: bytes) -> bytes:
    assert len(state_in) == 16
    payload = marker + state_in
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)
    if marker == b"M":
        evt = log_parser.find_event(events, module="aes", event="mixcolumns")
    else:
        evt = log_parser.find_event(events, module="aes",
                                    event="invmixcolumns")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 16
    return out


def test_mixcolumns_kat(artifacts: build.BuildArtifacts) -> None:
    """Pack 4 column vectors into one 16-byte state, check expected
    output byte-for-byte."""
    # Use the first 4 vectors as the 4 columns of a single state.
    cols_in = COLUMN_VECTORS[:4]
    state_in = b"".join(bytes(c[0]) for c in cols_in)
    expected = b"".join(bytes(c[1]) for c in cols_in)
    got = _run_mixcolumns(artifacts, state_in, marker=b"M")
    assert got == expected, (
        f"\ngot:      {got.hex()}"
        f"\nexpected: {expected.hex()}"
    )


def test_mixcolumns_kat_set2(artifacts: build.BuildArtifacts) -> None:
    """Same but with a different 4-column packing."""
    cols_in = COLUMN_VECTORS[2:6]
    state_in = b"".join(bytes(c[0]) for c in cols_in)
    expected = b"".join(bytes(c[1]) for c in cols_in)
    got = _run_mixcolumns(artifacts, state_in, marker=b"M")
    assert got == expected


def test_invmixcolumns_kat(artifacts: build.BuildArtifacts) -> None:
    """Reverse direction: feed the MixColumns *output* and expect the
    original *input* back. Uses the first 4 column vectors."""
    cols = COLUMN_VECTORS[:4]
    state_in = b"".join(bytes(c[1]) for c in cols)        # MC output
    expected = b"".join(bytes(c[0]) for c in cols)        # MC input
    got = _run_mixcolumns(artifacts, state_in, marker=b"m")
    assert got == expected, (
        f"\ngot:      {got.hex()}"
        f"\nexpected: {expected.hex()}"
    )


def test_round_trip(artifacts: build.BuildArtifacts) -> None:
    """invMixColumns(MixColumns(s)) == s for an arbitrary state."""
    state = bytes(range(16))
    fwd = _run_mixcolumns(artifacts, state, marker=b"M")
    rev = _run_mixcolumns(artifacts, fwd, marker=b"m")
    assert rev == state, (
        f"\ngot:  {rev.hex()}\nwant: {state.hex()}"
    )
