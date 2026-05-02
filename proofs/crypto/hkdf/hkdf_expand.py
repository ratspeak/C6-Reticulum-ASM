"""proofs/crypto/hkdf/hkdf_expand.py

angr binary-equivalence verifier for hkdf_expand (Tier C per ADR-0009).

HKDF-Expand iterates HMAC-SHA-256(PRK, T(i-1) || info || [i]) for
i = 1..N where N = ceil(L / 32). The asm orchestrates the chain via
hkdf_msg_buf and hkdf_t_buf scratch buffers and writes the truncated
OKM at okm_out.

Coverage:
  * RFC 5869 A.1 OKM (42 bytes from 32-byte PRK + 10-byte info)
  * RFC 5869 A.2 OKM (82 bytes — 3 T-blocks)
  * RFC 5869 A.3 OKM (42 bytes, empty info)
  * Single-block output (32 bytes)
  * Output exactly at block boundary (64, 96 bytes)
  * Maximum-length info (223 bytes per the asm's HKDF_MAX_INFO_LEN)
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

PRK_PTR  = 0x10010000
INFO_PTR = 0x10020000
OKM_PTR  = 0x10030000
SP_INIT  = 0x10100000
GP_INIT  = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

OKM_BUF_LEN = 512
OUT_GUARD_BYTE = 0xEE

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


def hkdf_expand_oracle(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 reference implementation."""
    n = (length + 31) // 32
    assert 1 <= n <= 255
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = hmac.new(prk,
                          t_prev + info + bytes([i]),
                          hashlib.sha256).digest()
        okm += t_prev
    return okm[:length]


def _make_state(proj: angr.Project, entry: int,
                prk: bytes, info: bytes, okm_len: int) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = PRK_PTR
    state.regs.a1 = len(prk)
    state.regs.a2 = INFO_PTR
    state.regs.a3 = len(info)
    state.regs.a4 = OKM_PTR
    state.regs.a5 = okm_len
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(PRK_PTR, prk)
    if info:
        state.memory.store(INFO_PTR, info)
    state.memory.store(OKM_PTR, bytes([OUT_GUARD_BYTE]) * OKM_BUF_LEN)
    return state


def _verify(proj: angr.Project, sym_addr: int,
            name: str, prk: bytes, info: bytes, okm_len: int) -> list[str]:
    failures: list[str] = []
    state = _make_state(proj, sym_addr, prk, info, okm_len)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    # 8 T-blocks max in our scenarios * ~2 SHA = ~30 SHA invocations.
    simgr.explore(find=RET_SENTINEL, num_find=1, n=200000)
    if not simgr.found:
        return [f"{name}: did not return"]
    end = simgr.found[0]

    out_blob = end.solver.eval(end.memory.load(OKM_PTR, OKM_BUF_LEN), cast_to=bytes)
    okm_actual = out_blob[:okm_len]
    okm_expected = hkdf_expand_oracle(prk, info, okm_len)
    if okm_actual != okm_expected:
        failures.append(
            f"{name}: OKM mismatch (length {okm_len}):\n"
            f"    got:      {okm_actual.hex()}\n"
            f"    expected: {okm_expected.hex()}")
    for off in range(okm_len, OKM_BUF_LEN):
        if out_blob[off] != OUT_GUARD_BYTE:
            failures.append(
                f"{name}: okm_out+{off} touched: got 0x{out_blob[off]:02x}")
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
    sym = proj.loader.find_symbol("hkdf_expand")
    if sym is None:
        print("FAIL: symbol hkdf_expand not present in ELF", file=sys.stderr)
        return 2

    a1_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    a2_prk = bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45cef76001490467101"
        "4a193f40c15fc244")
    a3_prk = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf965967 76afdb6377"
        "ac434c1c293ccb04".replace(" ", ""))

    scenarios: list[tuple[str, bytes, bytes, int]] = [
        ("RFC5869-A.1", a1_prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42),
        ("RFC5869-A.2", a2_prk,
         bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                       "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                       "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                       "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                       "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
         82),
        ("RFC5869-A.3-empty-info", a3_prk, b"", 42),
        ("32-byte-output-1block",  a1_prk, b"alpha", 32),
        ("64-byte-output-2blocks", a1_prk, b"alpha", 64),
        ("96-byte-output-3blocks", a1_prk, b"alpha", 96),
        ("max-info-223",           a1_prk, b"X" * 223, 32),
    ]

    all_failures: list[str] = []
    for name, prk, info, okm_len in scenarios:
        all_failures.extend(_verify(proj, sym.rebased_addr, name, prk, info, okm_len))

    if all_failures:
        print("FAIL: hkdf_expand binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: hkdf_expand binary-equivalence "
          f"({len(scenarios)} vectors: RFC 5869 A.1/A.2/A.3 + 4 boundary; "
          f"OKM matches RFC reference, no out-of-buffer writes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
