"""angr binary-equivalence verifier for x25519_field_add.

Drives the asm with controlled 10-limb arrays (zeros, edge cases,
random) and asserts decode_limbs(out) == (decode_limbs(a) +
decode_limbs(b)) mod p_25519.
"""
from __future__ import annotations

import logging
import random
import struct
import sys
from pathlib import Path

import angr
import archinfo

for noisy in ("angr", "cle", "pyvex", "claripy", "pcode"):
    logging.getLogger(noisy).setLevel(logging.ERROR)

REPO_ROOT = Path(__file__).resolve().parents[3]
ELF_PATH = REPO_ROOT / "build" / "qemu-virt" / "firmware.elf"

sys.path.insert(0, str(Path(__file__).parent))
from _x25519_oracle import (
    decode_limbs, limbs_to_bytes, bytes_to_limbs, f_add,
)

OUT_PTR = 0x10010000
A_PTR   = 0x10020000
B_PTR   = 0x10030000
SP_INIT = 0x10100000
GP_INIT = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

CALLEE_SAVED = ["sp", "gp", "s0", "s1", "s2", "s3", "s4",
                "s5", "s6", "s7", "s8", "s9", "s10", "s11"]


def _load_project() -> angr.Project:
    arch = archinfo.ArchPcode("RISCV:LE:32:RV32IMC")
    return angr.Project(
        str(ELF_PATH),
        auto_load_libs=False,
        arch=arch,
        engine=angr.engines.UberEnginePcode,
    )


def _verify(proj, sym_addr, name: str,
            a_limbs: list[int], b_limbs: list[int]) -> list[str]:
    state = proj.factory.blank_state(
        addr=sym_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = OUT_PTR
    state.regs.a1 = A_PTR
    state.regs.a2 = B_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(A_PTR, limbs_to_bytes(a_limbs))
    state.memory.store(B_PTR, limbs_to_bytes(b_limbs))
    state.memory.store(OUT_PTR, b"\xcd" * 40)

    pre = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=200)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out_blob = end.solver.eval(end.memory.load(OUT_PTR, 40), cast_to=bytes)
    out_limbs = bytes_to_limbs(out_blob)

    expected = f_add(decode_limbs(a_limbs), decode_limbs(b_limbs))
    actual = decode_limbs(out_limbs)
    failures: list[str] = []
    if actual != expected:
        failures.append(
            f"{name}: integer mismatch: got 0x{actual:x}, expected 0x{expected:x}\n"
            f"        a_limbs:   {a_limbs}\n"
            f"        b_limbs:   {b_limbs}\n"
            f"        out_limbs: {out_limbs}")
    # Inputs unchanged.
    a_post = bytes_to_limbs(end.solver.eval(end.memory.load(A_PTR, 40), cast_to=bytes))
    b_post = bytes_to_limbs(end.solver.eval(end.memory.load(B_PTR, 40), cast_to=bytes))
    if a_post != a_limbs:
        failures.append(f"{name}: a buffer modified")
    if b_post != b_limbs:
        failures.append(f"{name}: b buffer modified")
    # Callee-saved regs preserved.
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre[r]:
            failures.append(f"{name}: register {r} changed")
    return failures


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found", file=sys.stderr)
        return 2
    proj = _load_project()
    sym = proj.loader.find_symbol("x25519_field_add")
    if sym is None:
        print("FAIL: symbol x25519_field_add missing", file=sys.stderr)
        return 2

    rng = random.Random(0xF1ED_ADD)
    # Limb values bounded to ±2^25 so addition stays in int32 (no overflow).
    def rlimbs():
        return [rng.randint(-(1 << 25), (1 << 25) - 1) & 0xFFFF_FFFF
                for _ in range(10)]

    scenarios: list[tuple[str, list[int], list[int]]] = [
        ("zero+zero",            [0]*10, [0]*10),
        ("seven+zero",           [7]+[0]*9, [0]*10),
        ("identity+identity",    [1]*10, [1]*10),
        ("alias-safe (a==b)",    [123, 456, 789, 0, 0, 0, 0, 0, 0, 0],
                                 [123, 456, 789, 0, 0, 0, 0, 0, 0, 0]),
    ]
    for i in range(8):
        scenarios.append((f"random[{i}]", rlimbs(), rlimbs()))

    all_failures: list[str] = []
    for name, a, b in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, a, b))

    if all_failures:
        print("FAIL: x25519_field_add binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: x25519_field_add ({len(scenarios)} scenarios; integer "
          "match against the oracle, inputs untouched, "
          f"{len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
