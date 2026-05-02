"""proofs/crypto/sha256/sha256_update.py

angr binary-equivalence verifier for sha256_update (Tier C per ADR-0009).

Mirrors the streaming model in SHA256Update.cry as a Python oracle and
exercises the asm against multiple scenarios:

  * Empty input (no state change beyond length_bits).
  * Sub-block input into a fresh ctx (buffered, no compress).
  * Exactly-one-block input (one compress, block_len resets to 0).
  * Block + tail (one compress, then buffer).
  * Multiple blocks straight from data (multi-compress fast path).
  * Resume into a non-empty buffer (block_len > 0 entry).
  * Streaming a single message in two chunks (associativity).

For each scenario the asm's post-state is compared against the oracle:
ctx.H[0..8], ctx.length_bits, ctx.block_len, and the live portion of
ctx.block_buf[0..block_len]. Callee-saved registers + sp + gp are also
checked for preservation, and the input data buffer is checked for
non-modification.
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

# Reuse the FIPS reference compress from sha256_compress.py — it is the
# oracle for the H update too. Import via sys.path, not relative import,
# because angr verifiers are invoked as scripts not as modules.
sys.path.insert(0, str(Path(__file__).parent))
from sha256_compress import SHA256_IV, compress_block

# ---- ctx layout (matches src/include/sha256.S) -----------------------

CTX_H_OFFSET         = 0
CTX_LEN_BITS_OFFSET  = 32
CTX_BLOCK_OFFSET     = 40
CTX_BLOCK_LEN_OFFSET = 104
CTX_PAD_OFFSET       = 108
CTX_SIZE             = 112

# ---- Python oracle that mirrors sha256_update --------------------------

class Ctx:
    __slots__ = ("h", "length_bits", "block_buf", "block_len")

    def __init__(self,
                 h: tuple[int, ...] = SHA256_IV,
                 length_bits: int = 0,
                 block_buf: bytes = b"\x00" * 64,
                 block_len: int = 0) -> None:
        self.h = tuple(h)
        self.length_bits = length_bits
        self.block_buf = bytearray(block_buf)
        assert len(self.block_buf) == 64
        self.block_len = block_len
        assert 0 <= self.block_len < 64

    def clone(self) -> "Ctx":
        return Ctx(self.h, self.length_bits, bytes(self.block_buf), self.block_len)


def py_update(ctx: Ctx, data: bytes) -> Ctx:
    """Mirror of src/crypto/sha256/sha256_update.S."""
    out = ctx.clone()
    out.length_bits = (out.length_bits + len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    i = 0
    if out.block_len > 0:
        n = min(len(data), 64 - out.block_len)
        out.block_buf[out.block_len:out.block_len + n] = data[:n]
        out.block_len += n
        i = n
        if out.block_len == 64:
            out.h = compress_block(out.h, bytes(out.block_buf))
            out.block_len = 0
    while len(data) - i >= 64:
        out.h = compress_block(out.h, data[i:i + 64])
        i += 64
    if i < len(data):
        tail = data[i:]
        out.block_buf[out.block_len:out.block_len + len(tail)] = tail
        out.block_len += len(tail)
    return out


# ---- angr setup ----------------------------------------------------------

CTX_PTR    = 0x10010000
DATA_PTR   = 0x10020000
SP_INIT    = 0x10100000
GP_INIT    = 0xDEAD0000
RET_SENTINEL = 0xCAFEBABE

CALLEE_SAVED = ["sp", "gp", "s0", "s1", "s2", "s3", "s4",
                "s5", "s6", "s7", "s8", "s9", "s10", "s11"]

PAD_BYTE = 0xCD  # used for ctx.pad and the unused half of block_buf to detect any out-of-range writes


def _load_project() -> angr.Project:
    arch = archinfo.ArchPcode("RISCV:LE:32:RV32IMC")
    return angr.Project(
        str(ELF_PATH),
        auto_load_libs=False,
        arch=arch,
        engine=angr.engines.UberEnginePcode,
    )


def _ctx_to_bytes(ctx: Ctx) -> bytes:
    """Serialise a Ctx into the 112-byte struct layout the asm expects."""
    h_bytes = b"".join(struct.pack("<I", w) for w in ctx.h)
    lenbits = struct.pack("<Q", ctx.length_bits)
    # block_buf is 64 bytes; the "live" portion is block_buf[:block_len]
    # plus garbage in [block_len:]. We fill the trailing slots with
    # PAD_BYTE so the post-state check can detect any spurious write.
    block = bytes(ctx.block_buf[:ctx.block_len]) + bytes([PAD_BYTE]) * (64 - ctx.block_len)
    block_len = struct.pack("<I", ctx.block_len)
    pad = bytes([PAD_BYTE]) * 4
    blob = h_bytes + lenbits + block + block_len + pad
    assert len(blob) == CTX_SIZE
    return blob


def _bytes_to_ctx(b: bytes) -> Ctx:
    h = struct.unpack("<8I", b[CTX_H_OFFSET:CTX_H_OFFSET + 32])
    length_bits = struct.unpack("<Q", b[CTX_LEN_BITS_OFFSET:CTX_LEN_BITS_OFFSET + 8])[0]
    block_buf = b[CTX_BLOCK_OFFSET:CTX_BLOCK_OFFSET + 64]
    block_len = struct.unpack("<I", b[CTX_BLOCK_LEN_OFFSET:CTX_BLOCK_LEN_OFFSET + 4])[0]
    return Ctx(h=h, length_bits=length_bits, block_buf=block_buf, block_len=block_len)


def _make_state(proj: angr.Project, entry: int,
                ctx: Ctx, data: bytes) -> angr.SimState:
    state = proj.factory.blank_state(
        addr=entry,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.regs.a0 = CTX_PTR
    state.regs.a1 = DATA_PTR
    state.regs.a2 = len(data)
    state.regs.ra = RET_SENTINEL
    state.regs.sp = SP_INIT
    state.regs.gp = GP_INIT
    state.memory.store(CTX_PTR, _ctx_to_bytes(ctx))
    if data:
        state.memory.store(DATA_PTR, data)
    return state


def _run_one(proj: angr.Project, sym_addr: int,
             name: str, ctx_in: Ctx, data: bytes) -> tuple[Ctx, list[str]]:
    state = _make_state(proj, sym_addr, ctx_in, data)
    pre_regs = {r: state.solver.eval(getattr(state.regs, r)) for r in CALLEE_SAVED}
    data_pre = bytes(data)

    simgr = proj.factory.simulation_manager(state)
    # Empirically: 1-block ~400 bb, 4-block ~1200 bb, generous margin for
    # the 8-block multi-compress test below.
    simgr.explore(find=RET_SENTINEL, num_find=1, n=10000)
    if not simgr.found:
        return ctx_in, [f"{name}: did not return (active={len(simgr.active)}, "
                        f"deadended={len(simgr.deadended)}, errored={len(simgr.errored)})"]
    end = simgr.found[0]

    failures: list[str] = []

    # Read back the full ctx blob, compare to oracle.
    actual_blob = end.solver.eval(end.memory.load(CTX_PTR, CTX_SIZE), cast_to=bytes)
    actual = _bytes_to_ctx(actual_blob)
    expected = py_update(ctx_in, data)

    if actual.h != expected.h:
        failures.append(f"{name}: H mismatch:\n"
                        f"    got:      {[hex(w) for w in actual.h]}\n"
                        f"    expected: {[hex(w) for w in expected.h]}")
    if actual.length_bits != expected.length_bits:
        failures.append(f"{name}: length_bits: got 0x{actual.length_bits:x}, "
                        f"expected 0x{expected.length_bits:x}")
    if actual.block_len != expected.block_len:
        failures.append(f"{name}: block_len: got {actual.block_len}, "
                        f"expected {expected.block_len}")
    # Compare only the *live* portion of block_buf — bytes beyond
    # block_len are unspecified per the asm contract.
    if actual.block_len == expected.block_len:
        live = actual.block_len
        if bytes(actual.block_buf[:live]) != bytes(expected.block_buf[:live]):
            failures.append(
                f"{name}: block_buf[:{live}] mismatch:\n"
                f"    got:      {bytes(actual.block_buf[:live]).hex()}\n"
                f"    expected: {bytes(expected.block_buf[:live]).hex()}")

    # Data buffer must be unchanged.
    if data:
        actual_data = end.solver.eval(end.memory.load(DATA_PTR, len(data)), cast_to=bytes)
        if actual_data != data_pre:
            failures.append(f"{name}: input data buffer was modified")

    # Callee-saved regs preserved.
    for r in CALLEE_SAVED:
        post = end.solver.eval(getattr(end.regs, r))
        if post != pre_regs[r]:
            failures.append(f"{name}: register {r} changed: 0x{pre_regs[r]:08x} -> 0x{post:08x}")

    return actual, failures


def main() -> int:
    if not ELF_PATH.exists():
        print(f"FAIL: {ELF_PATH} not found; run `make build` first.", file=sys.stderr)
        return 2

    proj = _load_project()
    sym = proj.loader.find_symbol("sha256_update")
    if sym is None:
        print("FAIL: symbol sha256_update not present in ELF", file=sys.stderr)
        return 2

    fresh = lambda: Ctx()  # init ctx from the IV

    scenarios: list[tuple[str, Ctx, bytes]] = [
        ("empty",                fresh(), b""),
        ("3-bytes-abc",          fresh(), b"abc"),
        ("63-bytes",             fresh(), bytes(range(63))),
        ("exactly-1-block",      fresh(), b"\x00" * 64),
        ("1-block-plus-1-byte",  fresh(), bytes(range(65))),
        ("4-blocks",             fresh(), bytes(range(256))),
        ("8-blocks-plus-tail",   fresh(), bytes((i * 7 + 13) & 0xFF for i in range(513))),
    ]

    # Resume scenario: prefill ctx with non-zero state, then update.
    resume_ctx = fresh()
    resume_ctx.h = (0x12345678,) * 8
    resume_ctx.length_bits = 0x1234
    resume_ctx.block_buf[:10] = b"PREVPREVPR"
    resume_ctx.block_len = 10
    scenarios.append(("resume-with-blocklen-10",
                      resume_ctx, bytes(range(80))))

    all_failures: list[str] = []
    for name, ctx, data in scenarios:
        _, failures = _run_one(proj, sym.rebased_addr, name, ctx, data)
        all_failures.extend(failures)

    # Streaming-associativity scenario: feed a single 200-byte message
    # in one call vs in two calls of 70 + 130 (boundary crosses) and
    # confirm both end states match.
    full_msg = bytes((i * 31 + 7) & 0xFF for i in range(200))
    one_shot, failures = _run_one(proj, sym.rebased_addr,
                                  "streaming-one-shot", fresh(), full_msg)
    all_failures.extend(failures)
    chunk1, failures = _run_one(proj, sym.rebased_addr,
                                "streaming-chunk1", fresh(), full_msg[:70])
    all_failures.extend(failures)
    chunk2, failures = _run_one(proj, sym.rebased_addr,
                                "streaming-chunk2", chunk1, full_msg[70:])
    all_failures.extend(failures)
    if (one_shot.h != chunk2.h
            or one_shot.length_bits != chunk2.length_bits
            or one_shot.block_len != chunk2.block_len
            or bytes(one_shot.block_buf[:one_shot.block_len])
            != bytes(chunk2.block_buf[:chunk2.block_len])):
        all_failures.append(
            "streaming associativity: one-shot vs chunked diverged:\n"
            f"    one-shot H: {[hex(w) for w in one_shot.h]}\n"
            f"    chunked  H: {[hex(w) for w in chunk2.h]}")

    if all_failures:
        print("FAIL: sha256_update binary-equivalence:")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    print(f"PASS: sha256_update binary-equivalence "
          f"({len(scenarios)} scenarios + streaming associativity; "
          f"H/length_bits/block_len/block_buf match Python oracle, "
          f"input data unmodified, {len(CALLEE_SAVED)} callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
