"""angr binary-equivalence verifier for x25519_decode_scalar."""
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

K_PTR   = 0x10010000
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


def _expected_clamp(k: bytes) -> bytes:
    out = bytearray(k)
    out[0] &= 0xF8
    out[31] = (out[31] & 0x7F) | 0x40
    return bytes(out)


def _verify(proj, sym_addr, name, k: bytes) -> list[str]:
    state = proj.factory.blank_state(
        addr=sym_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = K_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(K_PTR, k)
    pre = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}
    pre_a0 = state.solver.eval(state.regs.a0)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=200)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out = end.solver.eval(end.memory.load(K_PTR, 32), cast_to=bytes)
    expected = _expected_clamp(k)
    failures: list[str] = []
    if out != expected:
        failures.append(f"{name}: got {out.hex()}, expected {expected.hex()}")
    # a0 must be preserved (the spec says preserves a0).
    post_a0 = end.solver.eval(end.regs.a0)
    if post_a0 != pre_a0:
        failures.append(f"{name}: a0 changed")
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
    sym = proj.loader.find_symbol("x25519_decode_scalar")
    if sym is None:
        print("FAIL: symbol x25519_decode_scalar missing", file=sys.stderr)
        return 2

    rng = random.Random(0xDEC_5CA)
    scenarios: list[tuple[str, bytes]] = [
        ("all-zero",     b"\x00" * 32),
        ("all-FF",       b"\xff" * 32),
        ("alice-priv",   bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645"
            "df4c2f87ebc0992ab177fba51db92c2a")),
        ("bob-priv",     bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee6"
            "6f3bb1292618b6fd1c2f8b27ff88e0eb")),
    ]
    for i in range(8):
        scenarios.append((f"random[{i}]", bytes(rng.getrandbits(8) for _ in range(32))))

    all_failures: list[str] = []
    for name, k in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, k))

    if all_failures:
        print("FAIL: x25519_decode_scalar:")
        for f in all_failures: print(f"  - {f}")
        return 1
    print(f"PASS: x25519_decode_scalar ({len(scenarios)} scenarios; "
          "byte-level clamping matches RFC 7748 §5).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
