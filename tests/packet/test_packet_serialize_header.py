"""Tests for src/packet/packet_serialize_header.S — round-trip skeleton."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "packet_serialize_header") > 0


def test_overflow_returns_minus_one(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_serialize_header")
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


def test_copies_byte_by_byte(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_serialize_header")
    assert re.search(r"\blbu\b\s+\w+,\s*0\(t1\)", body), body
    assert re.search(r"\bsb\b\s+\w+,\s*0\(t2\)", body), body


def test_returns_bytes_written(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_serialize_header")
    # Final mv a0, t0 returns raw_len (which we loaded into t0 at the top).
    assert re.search(r"\bmv\b\s+a0,\s*t0", body), body
