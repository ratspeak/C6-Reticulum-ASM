"""Tests for src/packet/packet_get_dest_hash.S — pointer arithmetic."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "packet_get_dest_hash") > 0


def test_loads_raw_ptr_and_dest_hash_off(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_get_dest_hash")
    # raw_ptr at offset 20, dest_hash_off at offset 4 (per packet.S).
    assert re.search(r"\blw\b\s+\w+,\s*20\(a0\)", body), body
    assert re.search(r"\blhu\b\s+\w+,\s*4\(a0\)", body), body


def test_returns_sum_in_a0(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="packet_get_dest_hash")
    assert re.search(r"\badd\b\s+a0,", body), body
    assert "ret" in body or "jalr\tzero" in body
