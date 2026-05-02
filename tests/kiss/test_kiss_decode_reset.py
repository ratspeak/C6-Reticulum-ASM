"""Tests for src/kiss/kiss_decode_reset.S — clear decoder state."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "kiss_decode_reset") > 0


def test_writes_zero_to_state_bytes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_decode_reset")
    # Three byte stores at offsets 0/1/2 of kiss_in_frame, plus a word
    # store of zero at kiss_buf_len.
    assert re.search(r"\bsb\b\s+zero,\s*0\(t0\)", body), body
    assert re.search(r"\bsb\b\s+zero,\s*1\(t0\)", body), body
    assert re.search(r"\bsb\b\s+zero,\s*2\(t0\)", body), body
    assert re.search(r"\bsw\b\s+zero,\s*0\(t1\)", body), body


def test_returns(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="kiss_decode_reset")
    assert "ret" in body or "jalr\tzero" in body
