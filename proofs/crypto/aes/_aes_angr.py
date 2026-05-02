"""proofs/crypto/aes/_aes_angr.py

Shared angr setup helper for the per-function AES verifiers.

Each verifier loads the firmware ELF, drives a single AES function with
controlled inputs, and compares its memory + register post-state against
the Python AES oracle in _aes_oracle.py. The boilerplate (project load,
state setup, return-sentinel detection, callee-saved snapshot) lives
here; per-function files only handle the specific input/output layout.
"""
from __future__ import annotations

import logging
from pathlib import Path

import angr
import archinfo

for noisy in ("angr", "cle", "pyvex", "claripy", "pcode"):
    logging.getLogger(noisy).setLevel(logging.ERROR)

REPO_ROOT = Path(__file__).resolve().parents[3]
ELF_PATH = REPO_ROOT / "build" / "qemu-virt" / "firmware.elf"

SP_INIT       = 0x10100000
GP_INIT       = 0xDEAD0000
RET_SENTINEL  = 0xCAFEBABE

CALLEE_SAVED = ["sp", "gp", "s0", "s1", "s2", "s3", "s4",
                "s5", "s6", "s7", "s8", "s9", "s10", "s11"]


def load_project() -> angr.Project:
    arch = archinfo.ArchPcode("RISCV:LE:32:RV32IMC")
    return angr.Project(
        str(ELF_PATH),
        auto_load_libs=False,
        arch=arch,
        engine=angr.engines.UberEnginePcode,
    )


def find_symbol(proj: angr.Project, name: str) -> int:
    sym = proj.loader.find_symbol(name)
    if sym is None:
        raise RuntimeError(f"symbol {name!r} not present in {ELF_PATH}")
    return sym.rebased_addr


def make_state(proj: angr.Project, entry: int,
               regs: dict[str, int],
               memory: list[tuple[int, bytes]]) -> angr.SimState:
    """Build a blank state at `entry`, set `regs`, and write `memory`."""
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    for r, v in regs.items():
        setattr(state.regs, r, v)
    for addr, data in memory:
        state.memory.store(addr, data)
    return state


def run_until_ret(proj: angr.Project, state: angr.SimState,
                  budget: int = 30000) -> angr.SimState | None:
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=RET_SENTINEL, num_find=1, n=budget)
    return simgr.found[0] if simgr.found else None


def snapshot_callee_saved(state: angr.SimState) -> dict[str, int]:
    return {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}


def check_callee_saved(end: angr.SimState,
                       pre: dict[str, int]) -> list[str]:
    failures = []
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre[r]:
            failures.append(
                f"register {r} changed: 0x{pre[r]:08x} -> 0x{post:08x}")
    return failures


def read_bytes(end: angr.SimState, addr: int, length: int) -> bytes:
    return end.solver.eval(end.memory.load(addr, length), cast_to=bytes)


def read_word_le(end: angr.SimState, addr: int) -> int:
    return end.solver.eval(end.memory.load(addr, 4, endness=archinfo.Endness.LE))
