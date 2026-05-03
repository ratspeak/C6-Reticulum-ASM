"""KAT for ed25519_sc_muladd executed under QEMU.

Frame: 'a' || a[32] || b[32] || c[32]. Emits 64 hex of (a*b + c) mod L.
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
    assert build.symbol_address(artifacts.elf, "ed25519_sc_muladd") > 0


def test_calls_sc_reduce(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="ed25519_sc_muladd")
    assert "ed25519_sc_reduce" in body, "sc_reduce not invoked"


def test_uses_mul(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="ed25519_sc_muladd")
    assert re.search(r"\bmul\b", body) and re.search(r"\bmulhu\b", body)


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


def _qemu_muladd(artifacts, a: int, b: int, c: int) -> int:
    a_b = a.to_bytes(32, "little")
    b_b = b.to_bytes(32, "little")
    c_b = c.to_bytes(32, "little")
    payload = b"a" + a_b + b_b + c_b
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="ed25519", event="sc_muladd")
    assert evt is not None, [e.raw for e in events]
    out = bytes.fromhex(evt.fields["hex"])
    return int.from_bytes(out, "little")


_KAT_CASES = [
    ("0_0_0",       0,        0,        0),
    ("1_1_0",       1,        1,        0),
    ("2_3_5",       2,        3,        5),
    ("L_minus_1*1", L - 1,    1,        0),
    ("ones",        L - 1,    L - 1,    L - 1),
    ("Lm1*Lm1+0",   L - 1,    L - 1,    0),
    ("aL_bL_cL_max",L - 1,    L - 1,    L - 1),
]


@pytest.mark.parametrize("name,a,b,c", _KAT_CASES, ids=[c[0] for c in _KAT_CASES])
def test_qemu_kat(artifacts, name, a, b, c):
    got = _qemu_muladd(artifacts, a, b, c)
    expected = (a * b + c) % L
    assert got == expected, (
        f"{name}: a*b+c = {a*b+c}\n"
        f"  got:  {got:064x}\n  want: {expected:064x}"
    )


def test_qemu_random(artifacts):
    """4 random scalar triples."""
    import random
    rng = random.Random(0xED25519A)
    for i in range(4):
        a = rng.randrange(L)
        b = rng.randrange(L)
        c = rng.randrange(L)
        got = _qemu_muladd(artifacts, a, b, c)
        expected = (a * b + c) % L
        assert got == expected, (
            f"random[{i}] a={a:064x} b={b:064x} c={c:064x}:\n"
            f"  got:  {got:064x}\n  want: {expected:064x}"
        )
