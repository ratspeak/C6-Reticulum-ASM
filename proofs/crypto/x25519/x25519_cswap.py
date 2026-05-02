"""angr binary-equivalence verifier for x25519_cswap."""
from __future__ import annotations

import logging
import random
import sys
from pathlib import Path

import angr
import archinfo

for noisy in ("angr", "cle", "pyvex", "claripy", "pcode"):
    logging.getLogger(noisy).setLevel(logging.ERROR)

REPO_ROOT = Path(__file__).resolve().parents[3]
ELF_PATH = REPO_ROOT / "build" / "qemu-virt" / "firmware.elf"

sys.path.insert(0, str(Path(__file__).parent))
from _x25519_oracle import limbs_to_bytes, bytes_to_limbs

A_PTR   = 0x10010000
B_PTR   = 0x10020000
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


def _verify(proj, sym_addr, name, swap, a_limbs, b_limbs) -> list[str]:
    state = proj.factory.blank_state(
        addr=sym_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = swap
    state.regs.a1 = A_PTR
    state.regs.a2 = B_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(A_PTR, limbs_to_bytes(a_limbs))
    state.memory.store(B_PTR, limbs_to_bytes(b_limbs))
    pre = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=200)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    a_post = bytes_to_limbs(end.solver.eval(end.memory.load(A_PTR, 40), cast_to=bytes))
    b_post = bytes_to_limbs(end.solver.eval(end.memory.load(B_PTR, 40), cast_to=bytes))
    expected_a = [x & 0xFFFF_FFFF for x in (b_limbs if swap else a_limbs)]
    expected_b = [x & 0xFFFF_FFFF for x in (a_limbs if swap else b_limbs)]
    failures: list[str] = []
    if a_post != expected_a:
        failures.append(f"{name}: a' wrong: got {a_post}, expected {expected_a}")
    if b_post != expected_b:
        failures.append(f"{name}: b' wrong: got {b_post}, expected {expected_b}")
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
    sym = proj.loader.find_symbol("x25519_cswap")
    if sym is None:
        print("FAIL: symbol x25519_cswap missing", file=sys.stderr)
        return 2

    rng = random.Random(0xC5_AB)
    def rlimbs():
        return [rng.getrandbits(32) for _ in range(10)]

    scenarios: list[tuple[str, int, list[int], list[int]]] = []
    for swap in (0, 1):
        scenarios += [
            (f"swap={swap},zero/zero",       swap, [0]*10, [0]*10),
            (f"swap={swap},a==b",            swap, [42]*10, [42]*10),
            (f"swap={swap},seven/eight",     swap, [7]*10, [8]*10),
        ]
        for i in range(4):
            scenarios.append((f"swap={swap},random[{i}]", swap, rlimbs(), rlimbs()))

    all_failures: list[str] = []
    for name, swap, a, b in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, swap, a, b))

    if all_failures:
        print("FAIL: x25519_cswap:")
        for f in all_failures: print(f"  - {f}")
        return 1
    print(f"PASS: x25519_cswap ({len(scenarios)} scenarios; "
          f"swap=0 preserves, swap=1 exchanges, "
          f"{len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
