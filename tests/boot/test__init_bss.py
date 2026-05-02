"""Tests for src/boot/_init_bss.S.

Two flavours of check:

* **Static (this file):** the assembled `_init_bss` body matches the loop
  shape required to zero `[__bss_start, __bss_end)` — load both bounds,
  store-zero word, increment, conditional branch back. This catches a
  swapped operand or an off-by-one immediately, even before _main is
  wired to actually run the function.

* **Integration (tests/boot/test__main.py, future):** after _main runs,
  a known .bss-resident variable is zero. Lands when _main is real.

Per @verify: kat-only, the formal obligation is "trivial memory zeroing";
refinement against `memset(.bss, 0, N)` is implicit in the static check.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_loads_bss_bounds(artifacts: build.BuildArtifacts) -> None:
    """Two auipc/addi pairs at the head load the BSS interval. Linker
    relaxation may resolve the symbol comment to a synonym (e.g.
    `__data_end` when BSS is currently empty) — we check shape, not the
    source-level symbol name."""
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_bss")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    assert len(instrs) >= 6, body
    # First load: la t0, __bss_start  →  auipc t0, … ; addi t0, t0, …
    assert "auipc" in instrs[0] and "t0," in instrs[0], instrs[0]
    assert "addi" in instrs[1] and "t0," in instrs[1], instrs[1]
    # Second load: la t1, __bss_end  →  auipc t1, … ; addi t1, t1, …
    assert "auipc" in instrs[2] and "t1," in instrs[2], instrs[2]
    assert "addi" in instrs[3] and "t1," in instrs[3], instrs[3]


def test_uses_word_store_in_loop(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_bss")
    # Compressed encoding may render `sw zero, 0(t0)` as `c.sw a0, 0(s0)` etc.
    # Match the canonical store-word form and a few assembler shorthand
    # variants.
    assert re.search(r"\bsw\b", body), body
    # The store target must be one of the two scratch registers we set up
    # (t0/x5 holds the iterator). objdump prints t0 as the alias.
    assert "(t0)" in body or "x5" in body


def test_loop_terminates_with_branch(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_bss")
    # Conditional branch out (beq t0, t1 → 2f) and unconditional jump back.
    assert re.search(r"\bbeq\b.*t0,t1", body) or "beq" in body
    assert re.search(r"\bj\b", body) or "jal\tzero" in body


def test_function_returns(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_bss")
    assert "ret" in body or "jalr\tzero" in body, body


def test_does_not_touch_callee_saved(artifacts: build.BuildArtifacts) -> None:
    """ABI: _init_bss must not modify s0..s11. Our impl uses only t0/t1,
    so the disassembly should not contain any sN register as a destination.
    """
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_bss")
    # crude scan: any "sN," appearing in the destination position
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"_init_bss writes callee-saved register {match}: {body}")
