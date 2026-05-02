"""KAT for x25519_field_mul executed under QEMU.

Frame layout: 'F' || a_limbs[40] || b_limbs[40] (each = 10 little-endian
int32). Emits 80 hex characters of the result limbs.

This is the Tier C bridge for x25519_field_mul: the angr pcode RV32IMC
engine miscompiles the 64-bit `mul + mulh + add-with-carry` chain (same
shape as x25519_field_mul121665), so we run the asm under QEMU and
compare against the Python oracle (which is in turn verified against the
algebraic Integer-form spec on 50 random inputs in the oracle
self-test). Static checks (no branches, ABI compliance, mul/mulh
present, stack frame balanced) live alongside.
"""
from __future__ import annotations

import random
import re
import struct
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
    assert build.symbol_address(artifacts.elf, "x25519_field_mul") > 0


def test_no_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_uses_mul_and_mulh(artifacts):
    """100 word multiplications use mul (low 32) + mulh (signed high 32)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul")
    assert re.search(r"\bmul\b", body), "missing mul"
    assert re.search(r"\bmulh\b", body), "missing mulh (signed)"
    assert re.search(r"\bmulhu\b", body), "missing mulhu (for ×19 fold)"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs} (net {net})"


def test_at_least_100_muls(artifacts):
    """fproduct does 10x10 = 100 word multiplications."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_mul")
    mul_count = len(re.findall(r"\bmul\b", body))
    assert mul_count >= 100, f"expected ≥100 mul, got {mul_count}"


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


def _qemu_field_mul(artifacts, a_limbs: list[int], b_limbs: list[int]) -> list[int]:
    payload = b"F" + limbs_to_bytes(a_limbs) + limbs_to_bytes(b_limbs)
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="x25519", event="field_mul")
    assert evt is not None, [e.raw for e in events]
    out_bytes = bytes.fromhex(evt.fields["hex"])
    assert len(out_bytes) == 40
    return bytes_to_limbs(out_bytes)


_KAT_CASES = [
    # (name, a, b)
    ("zero",        [0]*10, [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]),
    ("one_x_x",     [1]+[0]*9, [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]),
    ("seven_x_eleven", [7]+[0]*9, [11]+[0]*9),
    ("limb9_x_limb9", [0]*9+[0x01FFFFFF], [0]*9+[0x01FFFFFF]),
    ("limb1_x_limb1", [0,0x01FFFFFF]+[0]*8, [0,0x01FFFFFF]+[0]*8),  # both odd → ×2
]


@pytest.mark.parametrize("name,a,b", _KAT_CASES, ids=[c[0] for c in _KAT_CASES])
def test_qemu_kat(artifacts, name, a, b):
    got = _qemu_field_mul(artifacts, a, b)
    expected = field_mul_oracle(a, b)
    assert got == expected, (
        f"\n  got:      {got}"
        f"\n  expected: {expected}"
    )


def test_qemu_random_canonical(artifacts):
    """6 random nominal-width inputs: asm matches oracle byte-for-byte."""
    rng = random.Random(0xF1ED_AAAA)
    widths = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)
    for i in range(6):
        a = [rng.getrandbits(w) for w in widths]
        b = [rng.getrandbits(w) for w in widths]
        got = _qemu_field_mul(artifacts, a, b)
        expected = field_mul_oracle(a, b)
        assert got == expected, (
            f"random[{i}]: a={a} b={b}\n"
            f"  got:      {got}\n"
            f"  expected: {expected}"
        )
