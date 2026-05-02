"""proofs/crypto/sha256/sha256_init.py

angr binary-equivalence verifier for sha256_init (Tier C per ADR-0009).

Loads the firmware ELF, symbolically executes sha256_init at its symbol
address with a chosen ctx pointer, and checks that the post-state of
memory and callee-saved registers matches the Cryptol spec in
SHA256Init.cry. The angr engine is the pcode-based RV32IMC lifter from
Ghidra (pypcode), since stock pyvex has no RV32 frontend.

Post-conditions checked:

  1. mem[ctx +   0 .. +  32] == sha256_iv  (8 little-endian 32-bit words)
  2. mem[ctx +  32 .. +  40] == 0          (length_bits)
  3. mem[ctx + 104 .. + 108] == 0          (block_len)
  4. mem[ctx +  40 .. + 104] unchanged     (partial-block buffer untouched)
  5. mem[ctx + 108 .. + 112] unchanged     (pad untouched)
  6. callee-saved registers s0..s11, sp, gp preserved
  7. function returns within a bounded number of basic blocks (no infinite loop)

A FAIL exit code is non-zero and the failing assertion is printed.

Run standalone:
  toolchain/venv/bin/python proofs/crypto/sha256/sha256_init.py
or via dispatcher:
  ./verify sha256_init
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import angr
import archinfo
import claripy

# Silence angr's noisy info-level chatter so proof output is just the result.
for noisy in ("angr", "cle", "pyvex", "claripy", "pcode"):
    logging.getLogger(noisy).setLevel(logging.ERROR)

REPO_ROOT = Path(__file__).resolve().parents[3]
ELF_PATH = REPO_ROOT / "build" / "qemu-virt" / "firmware.elf"

# FIPS 180-4 §5.3.3 IV — kept here as the source-of-truth reference; the
# angr verifier compares the post-state H region against these literals
# (and SHA256Init.cry / sha256_init.saw cross-check the same values).
SHA256_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

CTX_H_OFFSET         = 0
CTX_LEN_BITS_OFFSET  = 32
CTX_BLOCK_OFFSET     = 40
CTX_BLOCK_LEN_OFFSET = 104
CTX_PAD_OFFSET       = 108
CTX_SIZE             = 112

CTX_PTR       = 0x10010000   # 16-byte aligned per @inputs
SP_INIT       = 0x10100000
GP_INIT       = 0xDEAD0000
RET_SENTINEL  = 0xCAFEBABE   # ra value; halts symbolic exec when ret is taken

CALLEE_SAVED = ["sp", "gp", "s0", "s1", "s2", "s3", "s4",
                "s5", "s6", "s7", "s8", "s9", "s10", "s11"]

SENTINEL_BYTE = 0xAA          # initial fill of the ctx buffer; any region
                               # left at 0xAA after the call was untouched


def _load_project() -> angr.Project:
    arch = archinfo.ArchPcode("RISCV:LE:32:RV32IMC")
    return angr.Project(
        str(ELF_PATH),
        auto_load_libs=False,
        arch=arch,
        engine=angr.engines.UberEnginePcode,
    )


def _make_state(proj: angr.Project, entry: int) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = CTX_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    # Pre-fill the ctx buffer with a sentinel so we can detect any write
    # outside the documented regions.
    state.memory.store(CTX_PTR, bytes([SENTINEL_BYTE] * CTX_SIZE))
    return state


def _eval_word(state: angr.SimState, addr: int) -> int:
    return state.solver.eval(state.memory.load(addr, 4, endness=archinfo.Endness.LE))


def _eval_byte(state: angr.SimState, addr: int) -> int:
    return state.solver.eval(state.memory.load(addr, 1))


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found; run `make build` first.",
              file=sys.stderr)
        return 2

    proj = _load_project()
    sym = proj.loader.find_symbol("sha256_init")
    if sym is None:
        print("FAIL: symbol sha256_init not present in ELF", file=sys.stderr)
        return 2

    state = _make_state(proj, sym.rebased_addr)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=200)

    if not simgr.found:
        print("FAIL: sha256_init did not return within 200 basic blocks "
              f"(active={len(simgr.active)}, deadended={len(simgr.deadended)}, "
              f"errored={len(simgr.errored)})", file=sys.stderr)
        return 1

    end = simgr.found[0]
    failures: list[str] = []

    # --- 1. H[0..8] equals the FIPS IV (LE).
    for i, expected in enumerate(SHA256_IV):
        addr = CTX_PTR + CTX_H_OFFSET + i * 4
        actual = _eval_word(end, addr)
        if actual != expected:
            failures.append(
                f"H[{i}] @0x{addr:08x}: got 0x{actual:08x}, "
                f"expected 0x{expected:08x}")

    # --- 2. length_bits = 0 (8 bytes).
    for off in (0, 4):
        addr = CTX_PTR + CTX_LEN_BITS_OFFSET + off
        actual = _eval_word(end, addr)
        if actual != 0:
            failures.append(
                f"length_bits+{off} @0x{addr:08x}: got 0x{actual:08x}, expected 0")

    # --- 3. block_len = 0 (4 bytes).
    addr = CTX_PTR + CTX_BLOCK_LEN_OFFSET
    actual = _eval_word(end, addr)
    if actual != 0:
        failures.append(
            f"block_len @0x{addr:08x}: got 0x{actual:08x}, expected 0")

    # --- 4 & 5. partial-block buffer and pad untouched (still SENTINEL_BYTE).
    untouched = [
        ("partial-block", CTX_BLOCK_OFFSET, 64),
        ("pad",           CTX_PAD_OFFSET,   4),
    ]
    for name, off, length in untouched:
        for b in range(length):
            addr = CTX_PTR + off + b
            actual = _eval_byte(end, addr)
            if actual != SENTINEL_BYTE:
                failures.append(
                    f"{name}+{b} @0x{addr:08x}: got 0x{actual:02x}, "
                    f"expected sentinel 0x{SENTINEL_BYTE:02x}")
                break  # one bad byte per region is enough

    # --- 6. callee-saved registers preserved.
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre_regs[r]:
            failures.append(
                f"register {r}: changed from 0x{pre_regs[r]:08x} to 0x{post:08x}")

    if failures:
        print("FAIL: sha256_init binary-equivalence:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("PASS: sha256_init binary-equivalence "
          f"(8 IV words, length_bits=0, block_len=0, "
          f"{len(CALLEE_SAVED)} callee-saved regs preserved, "
          "partial-block buffer + pad untouched).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
