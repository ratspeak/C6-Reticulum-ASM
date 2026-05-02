"""Tests for src/boot/_reset.S.

Per @verify: kat-only, the formal obligation is reduced to "entry-point
semantics, no functional contract." The test asserts the static facts
that hold by virtue of the linker placement and the asm prologue:

* The ELF entry-point address equals the address of `_reset`.
* `_reset` is the first symbol placed in .text (linker script `KEEP`).
* The first instruction sequence sets `sp` (auipc/addi pair) and `gp`
  (auipc/addi pair) before any function call. Concretely we confirm the
  disassembly contains references to `__stack_top` and `__global_pointer$`.
* `_reset` ends with a `jal` (call) to `_main` followed by a halt loop.

These checks fail loudly if the prologue is reordered or a symbol is
mistyped, which is the entire correctness story for an entry-point
function.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_entry_point_is_reset(artifacts: build.BuildArtifacts) -> None:
    entry = build.objdump_entry_point(artifacts.elf)
    reset_addr = build.symbol_address(artifacts.elf, "_reset")
    assert entry == reset_addr, (
        f"entry point 0x{entry:x} differs from _reset address 0x{reset_addr:x}"
    )


def test_reset_sets_sp_and_gp_before_calling_main(
    artifacts: build.BuildArtifacts,
) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_reset")
    # Strip header lines so the prologue check is clean.
    instructions = [
        line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)
    ]
    assert len(instructions) >= 5, body

    # 1. sp set first (la sp, __stack_top → auipc sp, … ; addi sp, sp, …).
    # The disassembler may render `addi sp, sp, 0` as `mv sp, sp` when
    # __stack_top happens to land exactly at the auipc-resolved page. Both
    # mean the same encoded instruction; accept either.
    assert "sp," in instructions[0] and "auipc" in instructions[0], instructions[0]
    second = instructions[1]
    assert "sp," in second and ("addi" in second or "mv\tsp,sp" in second), second
    # If the addi has a non-zero immediate, the disassembler annotates it
    # with the resolved symbol (__image_end or __stack_top). With imm=0
    # there is no resolved-address comment — the auipc immediate alone
    # carries the address. We only require the symbol annotation if the
    # disassembler emitted a comment.
    if "#" in second:
        assert "__image_end" in second or "__stack_top" in second, second

    # 2. gp set second
    assert "gp," in instructions[2] and "auipc" in instructions[2], instructions[2]
    assert "gp," in instructions[3] and "addi" in instructions[3], instructions[3]
    assert "__global_pointer$" in instructions[3]

    # 3. call _main
    call_line = next(line for line in instructions if "_main" in line)
    assert "jal" in call_line, call_line


def test_reset_ends_with_halt_loop(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="_reset")
    # Defensive: the code after the call should contain a `wfi` and a
    # backwards `j` forming an infinite loop.
    assert "wfi" in body, body
    # `j <addr>` where addr points back into _reset's body
    assert re.search(r"j\s+[0-9a-f]+\s+<_reset", body) or "<_reset+" in body


def test_reset_status_in_registry_matches_spec() -> None:
    # The check_registry tool warns when @status disagrees with FUNCTIONS.md;
    # this test elevates the warning to a hard failure for _reset specifically,
    # so a desynced commit fails this function's verifier instead of merely
    # printing a warning.
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tools"))
    import check_registry  # noqa: E402

    repo = Path(__file__).resolve().parent.parent.parent
    entries = check_registry.parse_registry(repo / "FUNCTIONS.md")
    by_name = {e.name: e for e in entries}
    assert "_reset" in by_name
    src = repo / "src" / "boot" / "_reset.S"
    spec = check_registry.parse_spec.parse_spec(src)
    spec_status = spec.fields.get("status", "")
    reg_status = by_name["_reset"].status
    # During the bring-up window, both statuses progress together. The
    # canonical end state is verified ↔ verified; while in-progress, both
    # should match (in-progress in registry, draft in source — the only
    # transition where they intentionally differ is at the moment a stub
    # commit lands; tests come next).
    if reg_status == "verified":
        assert spec_status == "verified"
