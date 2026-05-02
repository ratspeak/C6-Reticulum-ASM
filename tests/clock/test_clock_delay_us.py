"""Tests for src/clock/clock_delay_us.S.

Pure busy-wait via mtime modular subtraction. Static checks confirm the
function exists, computes us*10 (= shift-3 + shift-1), reads CLINT
mtime_lo, and contains a back-edge `bltu` (the spin loop). No
integration test: the boot path does not invoke clock_delay_us, and
adding a probe would alter timing for every other test. The function's
behaviour is fully determined by its 9-instruction body.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "clock_delay_us") > 0


def test_multiplies_by_ten_via_shifts(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_delay_us")
    # Expect `slli ?, a0, 3` (us*8) and `slli ?, a0, 1` (us*2). The exact
    # destination registers don't matter — the pair of shifts does.
    assert re.search(r"\bslli\b\s+\w+,\s*a0,\s*0x3\b", body) \
        or re.search(r"\bslli\b\s+\w+,\s*a0,\s*3\b", body), \
        f"missing slli a0, 3 (us*8): {body}"
    assert re.search(r"\bslli\b\s+\w+,\s*a0,\s*0x1\b", body) \
        or re.search(r"\bslli\b\s+\w+,\s*a0,\s*1\b", body), \
        f"missing slli a0, 1 (us*2): {body}"


def test_loads_mtime_low(artifacts: build.BuildArtifacts) -> None:
    """The function reads from CLINT mtime_lo at 0x0200bff8. Objdump
    annotates the address as a comment when the immediate is loaded."""
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_delay_us")
    # Either the literal CLINT_BASE upper half (`0x2000`) appears via lui,
    # or the resolved address comment 0x200bff8 / 200bff8 shows up.
    has_mtime = bool(
        re.search(r"\b0x?200bff8\b", body)
        or re.search(r"\blui\b\s+\w+,\s*0x2000\b", body)
        or re.search(r"\blui\b\s+\w+,\s*0x200c\b", body)
    )
    assert has_mtime, f"mtime_lo address not found in body: {body}"


def test_spin_loop_present(artifacts: build.BuildArtifacts) -> None:
    """A back-edge `bltu` is the spin condition (elapsed < delta)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_delay_us")
    assert re.search(r"\bbltu\b", body), f"missing bltu spin loop: {body}"


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_delay_us")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"clock_delay_us writes callee-saved {match}: {body}")


def test_no_stack_frame(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_delay_us")
    assert not re.search(r"\baddi\b\s+sp\b", body), \
        f"unexpected sp adjust in leaf: {body}"
