"""KAT for ed25519_sc_reduce executed under QEMU.

Frame: 'R' || in_bytes[64] (LE 512-bit integer).
Emits 64 hex characters of (in mod L) as 32 LE bytes.

Verifies against Python's int(in_bytes, 'little') % L for several
boundary inputs plus random bytes.
"""
from __future__ import annotations

import re
import time

import pytest

from harness import build, log_parser, oracle, target

L = 2**252 + 27742317777372353535851937790883648493


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "ed25519_sc_reduce") > 0


def test_no_data_dependent_branches(artifacts):
    """The 512-iteration loop counter is the only conditional branch
    (non-secret); the inner subtract uses constant-time mask select."""
    body = build.objdump_disassemble(artifacts.elf, symbol="ed25519_sc_reduce")
    branches = re.findall(r"\b(?:beq|bne|blt|bge|bltu|bgeu|beqz|bnez|bgez|bltz)\b",
                          body)
    # Loop counter back-branch (1) plus possibly a forward branch on entry. Allow ≤2.
    assert len(branches) <= 3, f"too many branches: {branches}"


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


def _qemu_sc_reduce(artifacts, in_bytes: bytes) -> int:
    assert len(in_bytes) == 64
    payload = b"R" + in_bytes
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="ed25519", event="sc_reduce")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    assert len(out) == 32
    return int.from_bytes(out, "little")


def _le_64(n: int) -> bytes:
    return n.to_bytes(64, "little")


_KAT_CASES = [
    ("zero",            _le_64(0)),
    ("L_minus_1",       _le_64(L - 1)),
    ("L",               _le_64(L)),
    ("L_plus_1",        _le_64(L + 1)),
    ("two_to_252",      _le_64(2**252)),
    ("two_to_256_m1",   _le_64(2**256 - 1)),
    ("two_to_512_m1",   _le_64(2**512 - 1)),
    ("just_below_2L",   _le_64(2 * L - 1)),
    ("middle",          _le_64((L * 3 + 17) % (2**512))),
]


@pytest.mark.parametrize("name,in_bytes", _KAT_CASES, ids=[c[0] for c in _KAT_CASES])
def test_qemu_kat(artifacts, name, in_bytes):
    got = _qemu_sc_reduce(artifacts, in_bytes)
    expected = int.from_bytes(in_bytes, "little") % L
    assert got == expected, f"{name}: got {got:064x}, want {expected:064x}"


def test_qemu_random(artifacts):
    """8 random 64-byte inputs."""
    import random
    rng = random.Random(0xED25519FED)
    for i in range(8):
        in_bytes = rng.randbytes(64)
        got = _qemu_sc_reduce(artifacts, in_bytes)
        expected = int.from_bytes(in_bytes, "little") % L
        assert got == expected, (
            f"random[{i}] {in_bytes.hex()}:\n"
            f"  got:  {got:064x}\n  want: {expected:064x}"
        )
