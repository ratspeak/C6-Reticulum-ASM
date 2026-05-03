"""End-to-end KAT for the SHA-512 family (init/update/final/compress)
executed under QEMU.

Frame: 'h' || message_bytes. Emits 128 hex characters of SHA-512(message).

Compares against Python's hashlib.sha512 on a battery of inputs that
exercise:
  - empty string
  - one-byte
  - exactly one 128-byte block
  - just-below-block boundary (forcing two padding blocks)
  - just-over-block boundary
  - the FIPS 180-4 §B.1 / NIST CAVP "abc" vector
  - longer multi-block inputs
"""
from __future__ import annotations

import hashlib
import re
import time

import pytest

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_symbols_exist(artifacts):
    for sym in ("sha512_init", "sha512_compress", "sha512_update",
                "sha512_final", "sha512_k"):
        assert build.symbol_address(artifacts.elf, sym) > 0, f"{sym} missing"


def test_compress_uses_loops(artifacts):
    """80-round main loop and W schedule loop both have back-branches."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha512_compress")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez)\b", body)
    # Schedule loop, 80-round loop, init-state loop, final loop, BE-load loop = 5 minimum.
    assert len(branches) >= 5, f"expected loops; got {len(branches)} branches"


# ---------- KATs ----------

def _run_frame(elf, frame: bytes, *, timeout: float = 60.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_sha512(artifacts, msg: bytes) -> bytes:
    payload = b"h" + msg
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="sha512", event="digest")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 64
    return out


_VECTORS = [
    ("empty",            b""),
    ("one_byte",         b"a"),
    ("abc",              b"abc"),
    ("block_boundary",   b"\x55" * 128),
    ("just_below",       b"\xaa" * 111),
    ("just_at_112",      b"\xaa" * 112),     # exactly the padding cutoff
    ("just_above",       b"\xaa" * 113),     # forces two trailing blocks
    ("two_blocks",       b"X" * 256),
    ("nist_56byte",      b"abcdbcdecdefdefgefghfghighijhijkijkljklm"
                         b"klmnlmnomnopnopq"),
]


@pytest.mark.parametrize("name,msg", _VECTORS, ids=[v[0] for v in _VECTORS])
def test_qemu_kat(artifacts, name, msg):
    got = _qemu_sha512(artifacts, msg)
    expected = hashlib.sha512(msg).digest()
    assert got == expected, (
        f"{name}:\n  got:  {got.hex()}\n  want: {expected.hex()}"
    )
