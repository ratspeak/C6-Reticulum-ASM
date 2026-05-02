"""proofs/crypto/hkdf/hkdf_extract.py

angr binary-equivalence verifier for hkdf_extract (Tier C per ADR-0009).

HKDF-Extract is HMAC-SHA-256(salt, IKM). The asm substitutes 32 zero
bytes for an empty salt before calling hmac_sha256. This verifier
exercises both salt forms against an in-script Python oracle that
mirrors the asm's substitution.

Coverage: RFC 5869 A.1 (13-byte salt), A.2 (80-byte salt — long
HMAC key path), A.3 (zero-length salt — substitution path), plus a
random short-salt vector.
"""
from __future__ import annotations

import hashlib
import hmac
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

SALT_PTR  = 0x10010000
IKM_PTR   = 0x10020000
PRK_PTR   = 0x10030000
SP_INIT   = 0x10100000
GP_INIT   = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

OUT_GUARD_BYTE = 0xEE
OUT_BUF_LEN = 64
PRK_LEN = 32

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


def _make_state(proj: angr.Project, entry: int,
                salt: bytes, ikm: bytes) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = SALT_PTR
    state.regs.a1 = len(salt)
    state.regs.a2 = IKM_PTR
    state.regs.a3 = len(ikm)
    state.regs.a4 = PRK_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    if salt:
        state.memory.store(SALT_PTR, salt)
    if ikm:
        state.memory.store(IKM_PTR, ikm)
    state.memory.store(PRK_PTR, bytes([OUT_GUARD_BYTE]) * OUT_BUF_LEN)
    return state


def _expected_prk(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _verify(proj: angr.Project, sym_addr: int,
            name: str, salt: bytes, ikm: bytes) -> list[str]:
    failures: list[str] = []
    state = _make_state(proj, sym_addr, salt, ikm)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=30000)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out_blob = end.solver.eval(end.memory.load(PRK_PTR, OUT_BUF_LEN), cast_to=bytes)
    prk_actual = out_blob[:PRK_LEN]
    prk_expected = _expected_prk(salt, ikm)
    if prk_actual != prk_expected:
        failures.append(
            f"{name}: PRK mismatch:\n"
            f"    got:      {prk_actual.hex()}\n"
            f"    expected: {prk_expected.hex()}")
    for off in range(PRK_LEN, OUT_BUF_LEN):
        if out_blob[off] != OUT_GUARD_BYTE:
            failures.append(
                f"{name}: prk_out+{off} touched: got 0x{out_blob[off]:02x}")
            break
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre_regs[r]:
            failures.append(f"{name}: register {r} changed")
    return failures


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found; run `make build` first.", file=sys.stderr)
        return 2
    proj = _load_project()
    sym = proj.loader.find_symbol("hkdf_extract")
    if sym is None:
        print("FAIL: symbol hkdf_extract not present in ELF", file=sys.stderr)
        return 2

    rng = random.Random(0x4845_4144)
    scenarios: list[tuple[str, bytes, bytes]] = [
        ("RFC5869-A.1",
         bytes(range(0x0c + 1)),
         b"\x0b" * 22),
        ("RFC5869-A.2-long-salt",
         bytes(b for b in range(0x60, 0xb0)),
         bytes(b for b in range(0x00, 0x50))),
        ("RFC5869-A.3-empty-salt",
         b"",
         b"\x0b" * 22),
        ("random-short",
         bytes(rng.getrandbits(8) for _ in range(20)),
         bytes(rng.getrandbits(8) for _ in range(40))),
    ]

    all_failures: list[str] = []
    for name, salt, ikm in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, salt, ikm))

    if all_failures:
        print("FAIL: hkdf_extract binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: hkdf_extract binary-equivalence "
          f"({len(scenarios)} vectors: RFC 5869 A.1/A.2/A.3 + random; "
          f"PRK matches Python hmac.new with zero-salt substitution).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
