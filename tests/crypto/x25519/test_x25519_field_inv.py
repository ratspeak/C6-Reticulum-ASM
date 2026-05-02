"""KAT for x25519_field_inv executed under QEMU.

Frame layout: 'i' || a_limbs[40]. Emits 80 hex characters of inv(a) limbs.

Tier C bridge (the angr pcode RV32IMC engine miscompiles the 64-bit
mul/mulh chains used by the underlying field_mul/field_sq, so we run
the asm under QEMU and check the algebraic round-trip identity
a · inv(a) ≡ 1 (mod p) using the algebraic-spec-validated Python
field_mul oracle).
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
    decode_limbs, field_mul_oracle, limbs_to_bytes, bytes_to_limbs, P,
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "x25519_field_inv") > 0


def test_data_independent_branches(artifacts):
    """Loops live at fixed iteration counts (the public exponent p-2);
    body must contain no branch on register-loaded data."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_inv")
    # No conditional branches: the macro expansion fully unrolls all
    # squarings, so the body is straight-line `call` sequences.
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_calls_field_sq_and_field_mul(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_inv")
    assert "x25519_field_sq" in body, "field_sq not invoked"
    assert "x25519_field_mul" in body, "field_mul not invoked"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_inv")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs}"


def test_squaring_chain_count(artifacts):
    """Donna `crecip` chain is 11 multiplications + ~265 squarings.
    Each `call` is to either field_sq or field_mul; we expect ≥260
    total invocations of these helpers (allowing some slack for tag
    addresses)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="x25519_field_inv")
    sq_calls  = len(re.findall(r"x25519_field_sq",  body))
    mul_calls = len(re.findall(r"x25519_field_mul", body))
    assert sq_calls + mul_calls >= 260, (
        f"expected ≥260 helper calls; got sq={sq_calls} mul={mul_calls}"
    )


# ---------- QEMU round-trip ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 60.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_field_inv(artifacts, a_limbs: list[int]) -> list[int]:
    payload = b"i" + limbs_to_bytes(a_limbs)
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="x25519", event="field_inv")
    assert evt is not None, [e.raw for e in events]
    out_bytes = bytes.fromhex(evt.fields["hex"])
    assert len(out_bytes) == 40
    return bytes_to_limbs(out_bytes)


def _round_trip_one(artifacts, a_limbs: list[int]) -> None:
    inv_a_limbs = _qemu_field_inv(artifacts, a_limbs)
    product = field_mul_oracle(a_limbs, inv_a_limbs)
    decoded = decode_limbs(product)
    assert decoded == 1, (
        f"a · inv(a) decoded to {decoded}, expected 1\n"
        f"  a:      {a_limbs}\n"
        f"  inv(a): {inv_a_limbs}\n"
        f"  prod:   {product}"
    )


def test_inv_of_one(artifacts):
    """1^(p-2) ≡ 1 — special case the chain handles."""
    inv_one = _qemu_field_inv(artifacts, [1] + [0] * 9)
    decoded = decode_limbs(inv_one)
    assert decoded == 1, f"inv(1) decoded to {decoded}, expected 1"


def test_inv_of_two(artifacts):
    """2 · inv(2) ≡ 1 (mod p)."""
    _round_trip_one(artifacts, [2] + [0] * 9)


def test_inv_of_seven(artifacts):
    """7 · inv(7) ≡ 1 (mod p)."""
    _round_trip_one(artifacts, [7] + [0] * 9)


def test_inv_of_pi_canonical(artifacts):
    """A non-trivial limb pattern must round-trip."""
    _round_trip_one(artifacts, [3, 1, 4, 1, 5, 9, 2, 6, 5, 3])


def test_inv_random(artifacts):
    """3 random nominal-width inputs round-trip via field_mul."""
    rng = random.Random(0xF1ED_CCCC)
    widths = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)
    for i in range(3):
        a = [rng.getrandbits(w) for w in widths]
        # Ensure a ≠ 0 (decode != 0); negligible probability of failing.
        assert decode_limbs(a) != 0, f"random[{i}] decoded to 0"
        _round_trip_one(artifacts, a)
