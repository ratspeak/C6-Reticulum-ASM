"""angr binary-equivalence verifier for x25519_field_pack.

Drives the asm with concrete-but-varied limb arrays (canonical, post-add
overflow, post-sub negatives, RFC round-trip, random) and asserts the
emitted 32 bytes match the Python oracle (donna fcontract).
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
    field_pack_oracle, field_unpack_oracle, limbs_to_bytes,
)

OUT_PTR = 0x10010000
IN_PTR  = 0x10020000
SP_INIT = 0x10100000
GP_INIT = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

CALLEE_SAVED = ["sp", "gp", "s0", "s1", "s2", "s3", "s4",
                "s5", "s6", "s7", "s8", "s9", "s10", "s11"]

P_LIMBS_CANONICAL = [
    0x03FFFFED, 0x01FFFFFF, 0x03FFFFFF, 0x01FFFFFF, 0x03FFFFFF,
    0x01FFFFFF, 0x03FFFFFF, 0x01FFFFFF, 0x03FFFFFF, 0x01FFFFFF,
]


def _load_project() -> angr.Project:
    arch = archinfo.ArchPcode("RISCV:LE:32:RV32IMC")
    return angr.Project(
        str(ELF_PATH),
        auto_load_libs=False,
        arch=arch,
        engine=angr.engines.UberEnginePcode,
    )


def _verify(proj, sym_addr, name, in_limbs: list[int]) -> list[str]:
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
    state.memory.store(IN_PTR, limbs_to_bytes(in_limbs))
    state.memory.store(OUT_PTR, b"\xcd" * 32)
    pre = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=2000)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out_bytes = end.solver.eval(end.memory.load(OUT_PTR, 32), cast_to=bytes)
    expected = field_pack_oracle(in_limbs)
    failures: list[str] = []
    if out_bytes != expected:
        failures.append(f"{name}: mismatch:\n"
                        f"    got:      {out_bytes.hex()}\n"
                        f"    expected: {expected.hex()}")
    in_post = end.solver.eval(end.memory.load(IN_PTR, 40), cast_to=bytes)
    if in_post != limbs_to_bytes(in_limbs):
        failures.append(f"{name}: input limbs buffer modified")
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre[r]:
            failures.append(f"{name}: register {r} changed "
                            f"(pre {pre[r]:08x}, post {post:08x})")
    return failures


def _signed_to_u32(v: int) -> int:
    return v & 0xFFFF_FFFF


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found", file=sys.stderr)
        return 2
    proj = _load_project()
    sym = proj.loader.find_symbol("x25519_field_pack")
    if sym is None:
        print("FAIL: symbol x25519_field_pack missing", file=sys.stderr)
        return 2

    rng = random.Random(0xF1ED_FE)

    # Round-trip a real RFC 7748 wire (with bit 255 already clear).
    rfc_v1_u = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c")
    rfc_v1_limbs = field_unpack_oracle(rfc_v1_u)

    scenarios: list[tuple[str, list[int]]] = [
        ("zero",                   [0] * 10),
        ("canonical-7",            [7] + [0] * 9),
        ("canonical-p",            P_LIMBS_CANONICAL),
        ("canonical-p-minus-1",    [(P_LIMBS_CANONICAL[0] - 1)]
                                   + P_LIMBS_CANONICAL[1:]),
        ("two-times-p",            [_signed_to_u32(2 * l)
                                    for l in P_LIMBS_CANONICAL]),
        ("rfc7748-v1-roundtrip",   rfc_v1_limbs),
        ("limb0-overflow",         [0x07FFFFFF] + [0] * 9),  # 1 bit over
        ("alt-mask26",             [0x03FFFFFF, 0, 0x03FFFFFF, 0,
                                    0x03FFFFFF, 0, 0x03FFFFFF, 0,
                                    0x03FFFFFF, 0]),
        ("limb9-only-low",         [0] * 9 + [1]),
        ("limb9-max",              [0] * 9 + [0x01FFFFFF]),
        # Negative limbs (post-sub bit pattern). Signed -1 in two's complement.
        ("neg-one-limb0",          [_signed_to_u32(-1)] + [0] * 9),
        ("neg-everywhere",         [_signed_to_u32(-1)] * 10),
    ]

    # Random canonical limbs (each within nominal width).
    widths = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)
    for i in range(6):
        lim = [rng.getrandbits(w) for w in widths]
        scenarios.append((f"random-canonical[{i}]", lim))

    # Random limbs near nominal width with one limb slightly overflowing.
    for i in range(4):
        lim = [rng.getrandbits(w) for w in widths]
        idx = rng.randrange(10)
        lim[idx] |= (1 << widths[idx])  # set the bit just above nominal
        lim[idx] &= 0xFFFF_FFFF
        scenarios.append((f"random-mild-overflow[{i}]", lim))

    all_failures: list[str] = []
    for name, lim in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, lim))

    if all_failures:
        print("FAIL: x25519_field_pack:")
        for f in all_failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: x25519_field_pack ({len(scenarios)} scenarios; bytes match"
          " donna fcontract, input untouched).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
