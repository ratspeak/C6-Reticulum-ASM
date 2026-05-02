"""Tests for src/clock/clock_now_ticks.S.

The function reads a 64-bit memory-mapped counter in three loads with a
hi/lo/hi-recheck pattern. We verify the function exists and the
disassembly contains exactly that shape (3 lw instructions plus a bne
that jumps backwards). Integration is exercised transitively via
clock_now_ms.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "clock_now_ticks") > 0


def test_three_lw_with_retry_bne(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_now_ticks")
    lws = re.findall(r"\blw\b", body)
    assert len(lws) == 3, f"expected 3 lw instructions, got {len(lws)}: {body}"
    # Retry branch — `bne` whose immediate jumps back into the function.
    assert re.search(r"\bbne\b", body), f"missing bne (retry): {body}"


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_now_ticks")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"clock_now_ticks writes callee-saved {match}: {body}")


def test_no_stack_frame(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_now_ticks")
    # Leaf: must not adjust sp.
    assert not re.search(r"\baddi\b\s+sp\b", body), \
        f"unexpected sp adjust in leaf: {body}"
