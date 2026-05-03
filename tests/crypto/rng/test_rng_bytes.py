"""KAT for rng_bytes executed under QEMU.

Frame layout: 'r' || count[1]. The dispatcher calls rng_init then
rng_bytes(buf, count); the counter advances per 32-byte block.

Each test asserts the emitted bytes match
  sha256(SEED || u32_le(0)) || sha256(SEED || u32_le(1)) || ...
truncated to `count` bytes.
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


def _oracle(count: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < count:
        out += hashlib.sha256(SEED + struct.pack("<I", counter)).digest()
        counter += 1
    return out[:count]


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "rng_bytes") > 0


def test_calls_sha256(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_bytes")
    for sym in ("sha256_init", "sha256_update", "sha256_final"):
        assert sym in body, f"{sym} not invoked"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_bytes")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs}"


# ---------- QEMU KATs ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 30.0) -> list:
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


@pytest.mark.parametrize("count", [1, 16, 31, 32, 33, 64, 96, 100])
def test_oracle_match(artifacts, count):
    """rng_bytes(N) for N ∈ {1, 16, 31, 32, 33, 64, 96, 100} matches
    the sha256-counter oracle (full 32-byte blocks plus a partial)."""
    got = _qemu_rng(artifacts, count)
    expected = _oracle(count)
    assert got == expected, (
        f"count={count}:\n  got:  {got.hex()}\n  want: {expected.hex()}"
    )
