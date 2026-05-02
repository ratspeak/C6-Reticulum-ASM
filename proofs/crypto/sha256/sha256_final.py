"""proofs/crypto/sha256/sha256_final.py

angr binary-equivalence verifier for sha256_final (Tier C per ADR-0009).

Drives the asm with several pre-update'd ctx states (built via the
already-verified Python `py_update` mirror), runs sha256_final, and
asserts that the 32-byte digest written at out_ptr equals
hashlib.sha256(M).digest() for the originating message M.

Coverage:
  * empty message
  * "abc" (one-block padding)
  * 55-byte message (last position before two-block padding fires)
  * 56-byte message (boundary: 0x80 + zeros doesn't fit before byte 56)
  * 64-byte message (full block, two-block padding from fresh buffer)
  * 100-byte message (multi-block + tail < 56)
  * 119-byte message (multi-block + tail crossing 56)
  * 128-byte message (exact two-block message)

For each: digest matches hashlib, callee-saved regs preserved, and the
out_ptr buffer received exactly 32 bytes (no overrun).
"""
from __future__ import annotations

import hashlib
import logging
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
from sha256_compress import SHA256_IV, compress_block
from sha256_update import Ctx, py_update, _ctx_to_bytes, CTX_SIZE

# ---- angr setup ----------------------------------------------------------

CTX_PTR     = 0x10010000
OUT_PTR     = 0x10020000
SP_INIT     = 0x10100000
GP_INIT     = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

OUT_GUARD_BYTE = 0xEE
OUT_BUF_LEN = 64    # we allocate 64 to detect any past-end write of the 32-byte digest
DIGEST_LEN = 32

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


def _make_state(proj: angr.Project, entry: int, ctx: Ctx) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = CTX_PTR
    state.regs.a1 = OUT_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(CTX_PTR, _ctx_to_bytes(ctx))
    # Pre-fill the output buffer with a guard byte so we can detect any
    # write past the 32-byte digest region.
    state.memory.store(OUT_PTR, bytes([OUT_GUARD_BYTE]) * OUT_BUF_LEN)
    return state


def _verify(proj: angr.Project, sym_addr: int,
            name: str, msg: bytes) -> list[str]:
    failures: list[str] = []

    # Build the pre-final ctx state by running py_update on init.
    ctx = py_update(Ctx(), msg)

    state = _make_state(proj, sym_addr, ctx)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=10000)
    if not simgr.found:
        return [f"{name}: did not return (active={len(simgr.active)}, "
                f"deadended={len(simgr.deadended)}, errored={len(simgr.errored)})"]
    end = simgr.found[0]

    # Extract the digest written at out_ptr.
    out_blob = end.solver.eval(end.memory.load(OUT_PTR, OUT_BUF_LEN), cast_to=bytes)
    digest_actual = out_blob[:DIGEST_LEN]
    digest_expected = hashlib.sha256(msg).digest()
    if digest_actual != digest_expected:
        failures.append(
            f"{name}: digest mismatch:\n"
            f"    got:      {digest_actual.hex()}\n"
            f"    expected: {digest_expected.hex()}")

    # No write past byte 32 of out_ptr.
    for off in range(DIGEST_LEN, OUT_BUF_LEN):
        if out_blob[off] != OUT_GUARD_BYTE:
            failures.append(
                f"{name}: out_ptr+{off} touched: got 0x{out_blob[off]:02x}, "
                f"expected guard 0x{OUT_GUARD_BYTE:02x}")
            break

    # Callee-saved regs preserved.
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
    sym = proj.loader.find_symbol("sha256_final")
    if sym is None:
        print("FAIL: symbol sha256_final not present in ELF", file=sys.stderr)
        return 2

    # Cross-validate Python oracles before we depend on them.
    assert hashlib.sha256(b"").hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    scenarios: list[tuple[str, bytes]] = [
        ("empty",            b""),
        ("abc",              b"abc"),
        ("55-bytes",         bytes(range(55))),
        ("56-bytes",         bytes(range(56))),    # boundary: triggers two-block padding
        ("64-bytes-zero",    b"\x00" * 64),         # exact one block
        ("100-bytes",        bytes((i * 13 + 7) & 0xFF for i in range(100))),
        ("119-bytes",        bytes((i * 11 + 3) & 0xFF for i in range(119))),
        ("128-bytes",        bytes((i * 7 + 5) & 0xFF for i in range(128))),
        ("129-bytes",        bytes((i * 17 + 11) & 0xFF for i in range(129))),
    ]

    all_failures: list[str] = []
    for name, msg in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, msg))

    if all_failures:
        print("FAIL: sha256_final binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: sha256_final binary-equivalence "
          f"({len(scenarios)} messages from 0..129 bytes; digest matches hashlib, "
          f"no write past out_ptr+32, {len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
