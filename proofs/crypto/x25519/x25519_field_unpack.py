"""angr binary-equivalence verifier for x25519_field_unpack."""
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
from _x25519_oracle import field_unpack_oracle, bytes_to_limbs

OUT_PTR = 0x10010000
IN_PTR  = 0x10020000
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


def _verify(proj, sym_addr, name, wire: bytes) -> list[str]:
    state = proj.factory.blank_state(
        addr=sym_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = OUT_PTR
    state.regs.a1 = IN_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(IN_PTR, wire)
    state.memory.store(OUT_PTR, b"\xcd" * 40)
    pre = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=500)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out_limbs = bytes_to_limbs(end.solver.eval(end.memory.load(OUT_PTR, 40), cast_to=bytes))
    expected = field_unpack_oracle(wire)
    failures: list[str] = []
    if out_limbs != expected:
        failures.append(f"{name}: mismatch:\n    got:      {out_limbs}\n    expected: {expected}")
    in_post = end.solver.eval(end.memory.load(IN_PTR, 32), cast_to=bytes)
    if in_post != wire:
        failures.append(f"{name}: input wire buffer modified")
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
    sym = proj.loader.find_symbol("x25519_field_unpack")
    if sym is None:
        print("FAIL: symbol x25519_field_unpack missing", file=sys.stderr)
        return 2

    rng = random.Random(0xF1ED_FE)
    scenarios: list[tuple[str, bytes]] = [
        ("all-zero",    b"\x00" * 32),
        ("all-FF",      b"\xff" * 32),
        ("counter",     bytes(range(32))),
        ("rfc7748-v1",  bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c"
            "726624ec26b3353b10a903a6d0ab1c4c")),
    ]
    for i in range(8):
        scenarios.append((f"random[{i}]",
                          bytes(rng.getrandbits(8) for _ in range(32))))

    all_failures: list[str] = []
    for name, w in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, w))

    if all_failures:
        print("FAIL: x25519_field_unpack:")
        for f in all_failures: print(f"  - {f}")
        return 1
    print(f"PASS: x25519_field_unpack ({len(scenarios)} scenarios; "
          "limbs match donna fexpand, input untouched).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
