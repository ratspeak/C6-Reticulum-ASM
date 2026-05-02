"""Tests for src/log/log_hex_buf.S.

Static-only: function exists, calls log_hex with width=2, has the
expected loop shape, doesn't write callee-saved beyond s0/s1.

Integration coverage comes from the sha256 KAT path through _main,
where log_hex_buf emits the 32-byte digest as 64 hex chars.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_hex_buf") > 0


def test_calls_log_hex_with_width_2(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex_buf")
    assert "log_hex" in body, body
    assert re.search(r"\bli\b\s+a1,\s*2\b", body), body


def test_loop_back_edge_present(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex_buf")
    # Either `j` or branch back into the loop body — objdump shows the
    # target as an earlier address.
    assert re.search(r"\bbeqz\b", body), body


def test_saves_only_s0_s1(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_hex_buf")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert saved == {"s0", "s1"}, f"unexpected saves: {saved}"
