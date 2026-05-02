"""Tests for src/kiss/kiss_encode_frame.S.

Static checks today; the differential test against
`tests/harness/oracle.kiss_encode` lands when there is a way to call
the asm function from the host (a per-function test firmware, or the
unicorn-engine path). For now the encode path's correctness is
implicitly covered by the kiss_decode_byte integration test, which
sends `oracle.kiss_encode(payload)` into the firmware and round-trips.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "kiss_encode_frame") > 0


def test_emits_fend_brackets(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_encode_frame")
    # FEND = 0xC0 = 192 is loaded as immediate at least twice (open + close).
    assert len(re.findall(r"\bli\b\s+\w+,\s*192\b", body)) >= 2, body


def test_emits_escape_pairs_for_fend_and_fesc(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_encode_frame")
    # FESC=219, TFEND=220, TFESC=221.
    assert re.search(r"\bli\b\s+\w+,\s*219\b", body), body
    assert re.search(r"\bli\b\s+\w+,\s*220\b", body), body
    assert re.search(r"\bli\b\s+\w+,\s*221\b", body), body


def test_returns_negative_one_on_overflow(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_encode_frame")
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


def test_returns_byte_count_via_subtract(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_encode_frame")
    # Result = write_cursor - dst_base. We compute as `sub a0, t0, a2`.
    assert re.search(r"\bsub\b\s+a0,\s*t0,\s*a2", body), body
