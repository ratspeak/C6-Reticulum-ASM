"""Tests for src/packet/packet_get_payload.S — payload pointer + length out."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "packet_get_payload") > 0


def test_writes_length_to_a1(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_get_payload")
    # `sh t1, 0(a1)` writes the length to *a1.
    assert re.search(r"\bsh\b\s+\w+,\s*0\(a1\)", body), body


def test_loads_payload_off_and_len(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_get_payload")
    assert re.search(r"\blhu\b\s+\w+,\s*8\(a0\)", body), body   # PAYLOAD_OFF
    assert re.search(r"\blhu\b\s+\w+,\s*12\(a0\)", body), body  # PAYLOAD_LEN
