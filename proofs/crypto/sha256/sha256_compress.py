"""proofs/crypto/sha256/sha256_compress.py

angr binary-equivalence verifier for sha256_compress (Tier C per ADR-0009).

Loads the firmware ELF, executes sha256_compress on multiple test vectors
(FIPS 180-4 §B.1 "abc", canonical empty-string single block, and several
random (H, M) pairs cross-checked against a Python reference compress),
and asserts:

  1. ctx->H[0..8] equals the FIPS-derived expected output for each vector.
  2. The 64-byte input block buffer is unchanged.
  3. Bytes outside ctx[0..32] (within the 112-byte ctx footprint) untouched.
  4. Callee-saved registers (sp, gp, s0..s11) are preserved.
  5. The function returns within a bounded number of basic blocks.

The Python `compress_block` below is FIPS 180-4 §6.2.2 implemented from
first principles. It is the oracle for #1 — independent of hashlib (whose
internal compress step is opaque) so we exercise the full input domain
of sha256_compress (any H, any M), not just well-padded message blocks.
"""
from __future__ import annotations

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

# ---- FIPS 180-4 constants ------------------------------------------------

SHA256_IV = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

SHA256_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

# ---- FIPS 180-4 §6.2.2 reference compress (Python oracle) -----------------

_M32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32


def _ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z)) & _M32


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _Sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _Sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _sigma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _sigma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def compress_block(H_in: tuple[int, ...], block_be: bytes) -> tuple[int, ...]:
    """FIPS 180-4 §6.2.2 — single-block compression, Python reference."""
    assert len(H_in) == 8
    assert len(block_be) == 64
    W = list(struct.unpack(">16I", block_be))
    for t in range(16, 64):
        W.append((_sigma1(W[t - 2]) + W[t - 7]
                  + _sigma0(W[t - 15]) + W[t - 16]) & _M32)
    a, b, c, d, e, f, g, h = H_in
    for t in range(64):
        T1 = (h + _Sigma1(e) + _ch(e, f, g) + SHA256_K[t] + W[t]) & _M32
        T2 = (_Sigma0(a) + _maj(a, b, c)) & _M32
        h, g, f = g, f, e
        e = (d + T1) & _M32
        d, c, b = c, b, a
        a = (T1 + T2) & _M32
    return tuple(
        (H_in[i] + v) & _M32
        for i, v in enumerate((a, b, c, d, e, f, g, h))
    )


# ---- Test vectors --------------------------------------------------------

def _abc_block_padded() -> bytes:
    # "abc" + 0x80 + 52 zero bytes + 8-byte BE length=24 bits.
    return b"abc" + b"\x80" + b"\x00" * 52 + b"\x00" * 7 + b"\x18"


def _empty_block_padded() -> bytes:
    # "" + 0x80 + 55 zero bytes + 8-byte BE length=0.
    return b"\x80" + b"\x00" * 55 + b"\x00" * 8


def _vectors() -> list[tuple[str, tuple[int, ...], bytes, tuple[int, ...]]]:
    abc_block = _abc_block_padded()
    empty_block = _empty_block_padded()
    abc_digest = (
        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
        0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
    )
    empty_digest = (
        0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
        0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855,
    )

    # Cross-check the canonical FIPS digests against our Python oracle —
    # if these mismatch, the rest of the angr proof is meaningless.
    assert compress_block(SHA256_IV, abc_block) == abc_digest
    assert compress_block(SHA256_IV, empty_block) == empty_digest

    # Random (H, M) pairs from a fixed seed — exercise compress on
    # arbitrary inputs, not just IV-derived ones. The expected H_out is
    # whatever our Python oracle computes; if the binary disagrees,
    # we've found a bug in the asm.
    import random
    rng = random.Random(0xC6_C6_C6)
    random_vectors = []
    for i in range(4):
        H = tuple(rng.getrandbits(32) for _ in range(8))
        M = bytes(rng.getrandbits(8) for _ in range(64))
        random_vectors.append((f"random[{i}]", H, M, compress_block(H, M)))

    return [
        ("FIPS-B.1-abc",  SHA256_IV, abc_block,   abc_digest),
        ("empty-block",   SHA256_IV, empty_block, empty_digest),
        *random_vectors,
    ]


# ---- angr setup ----------------------------------------------------------

CTX_PTR = 0x10010000
BLOCK_PTR = 0x10020000
SP_INIT = 0x10100000
GP_INIT = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

CTX_SIZE = 112  # full sha256_ctx footprint per src/include/sha256.S
SENTINEL_BYTE = 0xAA

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
                H_in: tuple[int, ...], block: bytes) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = CTX_PTR
    state.regs.a1 = BLOCK_PTR
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT

    # Pre-fill ctx with sentinel; write H_in into ctx[0..32].
    state.memory.store(CTX_PTR, bytes([SENTINEL_BYTE] * CTX_SIZE))
    h_bytes = b"".join(struct.pack("<I", w) for w in H_in)
    state.memory.store(CTX_PTR, h_bytes)

    # Write the 64-byte block as-is at BLOCK_PTR.
    state.memory.store(BLOCK_PTR, block)

    return state


def _verify_vector(proj: angr.Project, sym_addr: int,
                   name: str, H_in: tuple[int, ...],
                   block: bytes,
                   expected_H_out: tuple[int, ...]) -> list[str]:
    state = _make_state(proj, sym_addr, H_in, block)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r))
                for r in CALLEE_SAVED}

    simgr = proj.factory.simulation_manager(state)
    # 64 rounds + 16 BE-load + 48 schedule + prologue/epilogue → ~ a few
    # hundred basic blocks. 5000 is comfortable headroom.
    simgr.explore(find=RET_SENTINEL, num_find=1, n=5000)

    if not simgr.found:
        return [f"{name}: function did not return (active={len(simgr.active)}, "
                f"deadended={len(simgr.deadended)}, "
                f"errored={len(simgr.errored)})"]

    end = simgr.found[0]
    failures: list[str] = []

    # 1. ctx->H[0..8] post-state.
    for i, expected in enumerate(expected_H_out):
        addr = CTX_PTR + i * 4
        actual = end.solver.eval(
            end.memory.load(addr, 4, endness=archinfo.Endness.LE))
        if actual != expected:
            failures.append(
                f"{name}: H[{i}] @0x{addr:08x}: got 0x{actual:08x}, "
                f"expected 0x{expected:08x}")

    # 2. block buffer unchanged.
    for off in range(64):
        addr = BLOCK_PTR + off
        actual = end.solver.eval(end.memory.load(addr, 1))
        if actual != block[off]:
            failures.append(
                f"{name}: block[{off}] @0x{addr:08x}: got 0x{actual:02x}, "
                f"expected 0x{block[off]:02x}")
            break  # one bad byte per region is enough

    # 3. ctx[32..112] still sentinel.
    for off in range(32, CTX_SIZE):
        addr = CTX_PTR + off
        actual = end.solver.eval(end.memory.load(addr, 1))
        if actual != SENTINEL_BYTE:
            failures.append(
                f"{name}: ctx+{off} @0x{addr:08x}: got 0x{actual:02x}, "
                f"expected sentinel 0x{SENTINEL_BYTE:02x}")
            break

    # 4. callee-saved regs preserved.
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre_regs[r]:
            failures.append(
                f"{name}: register {r} changed: 0x{pre_regs[r]:08x} -> 0x{post:08x}")

    return failures


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found; run `make build` first.",
              file=sys.stderr)
        return 2

    proj = _load_project()
    sym = proj.loader.find_symbol("sha256_compress")
    if sym is None:
        print("FAIL: symbol sha256_compress not present in ELF",
              file=sys.stderr)
        return 2

    vectors = _vectors()
    all_failures: list[str] = []
    for name, H_in, block, expected_H_out in vectors:
        all_failures.extend(
            _verify_vector(proj, sym.rebased_addr,
                           name, H_in, block, expected_H_out))

    if all_failures:
        print("FAIL: sha256_compress binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: sha256_compress binary-equivalence "
          f"({len(vectors)} vectors: FIPS-B.1, empty, 4 random; "
          f"H_out matches Python oracle, block buffer + ctx[32..112] "
          f"untouched, {len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
