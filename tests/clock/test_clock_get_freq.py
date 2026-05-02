"""Tests for src/clock/clock_get_freq.S.

Pure literal-load. Static checks: function exists, body is `li a0, CPU_HZ;
ret`, no callee-saved writes, no stack frame.
"""

from __future__ import annotations

import re

import pytest

from harness import build

# Mirrors src/include/regs.S CPU_HZ for qemu-virt; if regs.S changes, this
# test must change in lockstep (intentional — the constant IS the contract).
QEMU_VIRT_CPU_HZ = 100_000_000


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "clock_get_freq") > 0


def test_loads_cpu_hz_constant(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_get_freq")
    # `li a0, 100000000` expands to `lui a0, 0x5f5e` + `addi a0, a0, 0x100`
    # since 100_000_000 = 0x5F5E100. objdump annotates the resolved
    # address with `# 5f5e100 <CPU_HZ>`. We accept either the hex value
    # or the symbol name as evidence.
    hex_value = f"{QEMU_VIRT_CPU_HZ:x}"  # "5f5e100"
    assert re.search(rf"\b{hex_value}\b", body) or "CPU_HZ" in body, \
        f"expected {hex_value} or CPU_HZ in disassembly: {body}"


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_get_freq")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"clock_get_freq writes callee-saved {match}: {body}")


def test_no_stack_frame(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_get_freq")
    assert not re.search(r"\baddi\b\s+sp\b", body), \
        f"unexpected sp adjust in leaf: {body}"
