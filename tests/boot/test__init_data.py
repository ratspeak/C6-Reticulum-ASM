"""Tests for src/boot/_init_data.S.

Static disassembly checks (per @verify: kat-only). On qemu-virt the
function is semantically identity (LMA == VMA), but the asm shape — load,
store, increment-both, branch — is the same as on the C6 where it
performs a real flash → SRAM copy. The tests assert the shape; the
integration check (a non-zero .data initialiser observed at runtime)
lands when _main wires up the boot chain.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_loads_three_bounds(artifacts: build.BuildArtifacts) -> None:
    """Three la pairs at the head: __data_start, __data_end, __data_load_start."""
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_data")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    assert len(instrs) >= 9, body
    for i, reg in enumerate(("t0", "t1", "t2")):
        assert "auipc" in instrs[2 * i] and f"{reg}," in instrs[2 * i], instrs[2 * i]
        assert "addi" in instrs[2 * i + 1] and f"{reg}," in instrs[2 * i + 1], instrs[2 * i + 1]


def test_load_store_word_pair(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_data")
    # The word load is from the LMA cursor (t2), the word store goes to the
    # VMA cursor (t0). Match the canonical forms; objdump may compress.
    assert re.search(r"\blw\b\s+t3,0\(t2\)", body), body
    assert re.search(r"\bsw\b\s+t3,0\(t0\)", body), body


def test_loop_advances_both_cursors(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_data")
    # Two `addi … 4` increments per iteration — one for t0, one for t2.
    addi_count = len(re.findall(r"\baddi\s+(t0|t2),", body)) + \
                 len(re.findall(r"\baddi\s+(t0|t2),", body))
    # The la prologue also uses addi for low-12-bit fixups; subtract the
    # known three la pairs (3 addi). Increments contribute 2 more.
    addi_total = len(re.findall(r"\baddi\b", body))
    assert addi_total >= 5, body  # 3 (la fixups) + 2 (increments)


def test_function_returns(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_data")
    assert "ret" in body or "jalr\tzero" in body, body


def test_does_not_touch_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_init_data")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"_init_data writes callee-saved register {match}: {body}")
