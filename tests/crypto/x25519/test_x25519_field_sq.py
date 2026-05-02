"""KAT for x25519_field_sq executed under QEMU.

Frame layout: 'Q' || a_limbs[40]. Emits 80 hex characters of the result.

The asm is a 2-instruction wrapper (mv a2, a1; tail x25519_field_mul),
so correctness reduces to (1) the wrapper is a valid tail call that
preserves a0/a1 semantics, and (2) field_mul is verified. The QEMU KAT
exercises the wrapper end-to-end on inputs where a*a hits each branch
of the (i,j)-both-odd ×2 doubling.
"""
from __future__ import annotations

import random
import re
import sys
import time
from pathlib import Path

import pytest

from harness import build, log_parser, oracle, target

sys.path.insert(0, str(Path(__file__).resolve().parents[2] /
                       "../proofs/crypto/x25519"))
from _x25519_oracle import (  # type: ignore
    field_mul_oracle, limbs_to_bytes, bytes_to_limbs,
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_sq") > 0


def test_no_local_stack_frame(artifacts):
    """Tail-call wrapper: no sp adjustment in field_sq itself."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_sq")
    assert not re.search(r"addi\s+sp\s*,\s*sp\s*,\s*-?\d+", body), \
        f"unexpected stack frame in field_sq: {body}"


def test_tail_calls_field_mul(artifacts):
    """Body must end with a jump (not a call) to x25519_field_mul."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_sq")
    assert "x25519_field_mul" in body, f"field_mul not referenced: {body}"
    # tail expands to `j` or `jal x0,...` (no return-address save).
    assert re.search(r"\bj\b", body) or "x0," in body, \
        f"expected unconditional jump for tail call: {body}"


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_sq")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


# ---------- QEMU KAT ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 30.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_field_sq(artifacts, a_limbs: list[int]) -> list[int]:
    payload = b"Q" + limbs_to_bytes(a_limbs)
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="x25519", event="field_sq")
    assert evt is not None, [e.raw for e in events]
    out_bytes = bytes.fromhex(evt.fields["hex"])
    assert len(out_bytes) == 40
    return bytes_to_limbs(out_bytes)


_KAT_CASES = [
    ("zero",         [0]*10),
    ("one",          [1]+[0]*9),
    ("seven",        [7]+[0]*9),
    ("limb1_only",   [0, 0x01FFFFFF] + [0]*8),  # both-odd ×2 path on (1,1)
    ("limb9_only",   [0]*9 + [0x01FFFFFF]),
    ("pi_canonical", [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]),
]


@pytest.mark.parametrize("name,a", _KAT_CASES, ids=[c[0] for c in _KAT_CASES])
def test_qemu_kat(artifacts, name, a):
    got = _qemu_field_sq(artifacts, a)
    expected = field_mul_oracle(a, a)
    assert got == expected, (
        f"\n  got:      {got}"
        f"\n  expected: {expected}"
    )


def test_qemu_random_canonical(artifacts):
    """6 random nominal-width inputs: field_sq(a) == field_mul(a, a)."""
    rng = random.Random(0xF1ED_BBBB)
    widths = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)
    for i in range(6):
        a = [rng.getrandbits(w) for w in widths]
        got = _qemu_field_sq(artifacts, a)
        expected = field_mul_oracle(a, a)
        assert got == expected, (
            f"random[{i}]: a={a}\n"
            f"  got:      {got}\n"
            f"  expected: {expected}"
        )
