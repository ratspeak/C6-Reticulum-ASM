"""Static + QEMU smoke tests for rng_init.

rng_init resets the deterministic-fake counter to zero. There's no
data-dependent behavior to verify algebraically; the pytest below
exercises the QEMU-driven `r` dispatcher tag (which itself calls
rng_init followed by rng_bytes), and asserts that after a fresh boot
the first 32 emitted bytes match sha256(SEED || 0).
"""
from __future__ import annotations

import hashlib
import re
import struct
import time

import pytest

from harness import build, log_parser, oracle, target

SEED = b"DETERMINISTIC_FAKE_RNG_FOR_QEMU" + b"\x00"
assert len(SEED) == 32


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "rng_init") > 0


def test_no_data_dependent_branches(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_init")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    assert not branches, f"unexpected branches: {branches}"


def test_seed_symbol_present(artifacts):
    """The DETERMINISTIC_FAKE_RNG marker must be in the linked image so
    a CI gate can refuse a release build that includes it."""
    assert build.symbol_address(artifacts.elf, "DETERMINISTIC_FAKE_RNG") > 0


# ---------- QEMU smoke (asserts the post-condition counter==0) ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 10.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_rng(artifacts, count: int) -> bytes:
    payload = b"r" + bytes([count])
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="rng", event="bytes")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == count
    return out


def test_first_block_is_sha256_seed_zero_counter(artifacts):
    """After boot (rng_init was called), the first 32 emitted bytes
    must equal sha256(SEED || u32_le(0))."""
    expected = hashlib.sha256(SEED + struct.pack("<I", 0)).digest()
    got = _qemu_rng(artifacts, 32)
    assert got == expected, f"\n  got:  {got.hex()}\n  want: {expected.hex()}"
