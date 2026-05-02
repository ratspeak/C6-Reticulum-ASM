"""Tests for src/uart/uart_rx_byte.S — polled NS16550A read."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "uart_rx_byte") > 0


def test_loads_uart0_base(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_rx_byte")
    assert re.search(r"\blui\b\s+t0,\s*0x10000\b", body), body


def test_polls_dr_bit(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_rx_byte")
    assert re.search(r"\blbu\b\s+t1,\s*5\(t0\)", body), body
    assert re.search(r"\bandi\b\s+t1,\s*t1,\s*1\b", body), body
    assert re.search(r"\bbeqz\b\s+t1", body), body


def test_reads_from_rbr_into_a0(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="uart_rx_byte")
    assert re.search(r"\blbu\b\s+a0,\s*0\(t0\)", body), body
