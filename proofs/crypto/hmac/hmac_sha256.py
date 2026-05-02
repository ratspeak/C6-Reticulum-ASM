"""proofs/crypto/hmac/hmac_sha256.py

angr binary-equivalence verifier for hmac_sha256 (Tier C per ADR-0009).

Drives the asm with key/message pairs from RFC 4231 plus randomized
short and long key vectors, and asserts that the 32-byte tag matches
Python's hmac.new(key, msg, hashlib.sha256).digest().

Coverage:
  * RFC 4231 TC1 (20-byte 0x0b key, "Hi There")
  * RFC 4231 TC2 ("Jefe", "what do ya want for nothing?")
  * RFC 4231 TC3 (20*0xaa key, 50*0xdd msg)
  * RFC 4231 TC4 (25-byte ascending key, 50*0xcd msg)
  * RFC 4231 TC6 (131-byte key — long-key path)
  * RFC 4231 TC7 (131-byte key, 152-byte msg)
  * Empty key, empty message
  * Random short-key + random msg
  * Random exactly-64-byte key (boundary, no hash-down)
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

# ---- angr setup ----------------------------------------------------------

KEY_PTR  = 0x10010000
MSG_PTR  = 0x10020000
OUT_PTR  = 0x10030000
SP_INIT  = 0x10100000
GP_INIT  = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

OUT_GUARD_BYTE = 0xEE
OUT_BUF_LEN = 64
TAG_LEN = 32

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
                key: bytes, msg: bytes) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = KEY_PTR
    state.regs.a1 = len(key)
    state.regs.a2 = MSG_PTR
    state.regs.a3 = len(msg)
    state.regs.a4 = OUT_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    if key:
        state.memory.store(KEY_PTR, key)
    if msg:
        state.memory.store(MSG_PTR, msg)
    state.memory.store(OUT_PTR, bytes([OUT_GUARD_BYTE]) * OUT_BUF_LEN)
    return state


def _verify(proj: angr.Project, sym_addr: int,
            name: str, key: bytes, msg: bytes) -> list[str]:
    failures: list[str] = []
    state = _make_state(proj, sym_addr, key, msg)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    # HMAC = ~2 sha256 invocations + key prep. 30000 bb generous.
    simgr.explore(find=RET_SENTINEL, num_find=1, n=30000)
    if not simgr.found:
        return [f"{name}: did not return (active={len(simgr.active)}, "
                f"deadended={len(simgr.deadended)}, errored={len(simgr.errored)})"]
    end = simgr.found[0]

    out_blob = end.solver.eval(end.memory.load(OUT_PTR, OUT_BUF_LEN), cast_to=bytes)
    tag_actual = out_blob[:TAG_LEN]
    tag_expected = hmac.new(key, msg, hashlib.sha256).digest()
    if tag_actual != tag_expected:
        failures.append(
            f"{name}: tag mismatch:\n"
            f"    got:      {tag_actual.hex()}\n"
            f"    expected: {tag_expected.hex()}")

    for off in range(TAG_LEN, OUT_BUF_LEN):
        if out_blob[off] != OUT_GUARD_BYTE:
            failures.append(
                f"{name}: out_ptr+{off} touched: got 0x{out_blob[off]:02x}, "
                f"expected guard 0x{OUT_GUARD_BYTE:02x}")
            break

    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre_regs[r]:
            failures.append(f"{name}: register {r} changed: 0x{pre_regs[r]:08x} -> 0x{post:08x}")

    return failures


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found; run `make build` first.", file=sys.stderr)
        return 2

    proj = _load_project()
    sym = proj.loader.find_symbol("hmac_sha256")
    if sym is None:
        print("FAIL: symbol hmac_sha256 not present in ELF", file=sys.stderr)
        return 2

    rng = random.Random(0x4d_46_43)

    scenarios: list[tuple[str, bytes, bytes]] = [
        ("RFC4231-TC1", b"\x0b" * 20, b"Hi There"),
        ("RFC4231-TC2", b"Jefe", b"what do ya want for nothing?"),
        ("RFC4231-TC3", b"\xaa" * 20, b"\xdd" * 50),
        ("RFC4231-TC4", bytes(range(1, 26)), b"\xcd" * 50),
        ("RFC4231-TC6", b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
        ("RFC4231-TC7", b"\xaa" * 131,
         b"This is a test using a larger than block-size key and a larger than block-size data. "
         b"The key needs to be hashed before being used by the HMAC algorithm."),
        ("empty-key-empty-msg", b"", b""),
        ("64-byte-key-no-hash-down",
         bytes(rng.getrandbits(8) for _ in range(64)),
         bytes(rng.getrandbits(8) for _ in range(40))),
        ("random-short", bytes(rng.getrandbits(8) for _ in range(31)),
         bytes(rng.getrandbits(8) for _ in range(123))),
    ]

    all_failures: list[str] = []
    for name, key, msg in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, key, msg))

    if all_failures:
        print("FAIL: hmac_sha256 binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: hmac_sha256 binary-equivalence "
          f"({len(scenarios)} vectors: RFC 4231 TC1/2/3/4/6/7 + 3 boundary/random; "
          f"tag matches Python hmac.new, no write past out_ptr+32, "
          f"{len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
