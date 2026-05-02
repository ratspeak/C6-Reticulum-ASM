"""Tests for src/log/log_bytes.S — loop calling log_hex per byte."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_bytes") > 0


def test_calls_log_hex(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_bytes")
    assert "log_hex" in body, body


def test_emits_space_separator(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_bytes")
    # ASCII space = 32; passed via a0 to uart_tx_byte.
    assert re.search(r"\bli\b\s+a0,\s*32\b", body), body
    assert "uart_tx_byte" in body, body


def test_handles_empty_buffer(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_bytes")
    # The early `beqz s1, .Ldone` short-circuit covers len=0 without
    # touching the cursor.
    assert re.search(r"\bbeqz\b\s+s1", body), body


def test_two_digit_width(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_bytes")
    # log_hex is called with width=2 (a1 = 2) — two `li a1, 2`.
    assert len(re.findall(r"\bli\b\s+a1,\s*2\b", body)) >= 1, body
