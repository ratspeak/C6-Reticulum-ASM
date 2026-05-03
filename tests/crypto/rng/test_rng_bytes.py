"""KAT for rng_bytes executed under QEMU.

`rng_bytes` is the HMAC-DRBG-SHA-256 generate operation per NIST
SP 800-90A Rev. 1 §10.1.2.5. The DRBG is instantiated by `rng_init`
from 48 bytes of `rng_entropy` (entropy_input(32) + nonce(16); null
personalization). On TARGET_QEMU_VIRT the entropy source is the
deterministic-fake CSPRNG `sha256(SEED || counter_le32)`, so the
DRBG output is fully reproducible and pinnable in a Python oracle.

Frame layout: 'r' || count[1]. The dispatcher calls `rng_init` then
`rng_bytes(buf, count)` once. Tests assert the emitted bytes match
the in-script HMAC-DRBG oracle (which itself is exercised against
the verified RFC 4231 / RFC 5869 / NIST CAVP HMAC and SHA-256
behaviour by the existing per-primitive Tier A proofs).
"""
from __future__ import annotations

import re
import time

import pytest

from harness import build, drbg_oracle, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


# ---------- static checks ----------

def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "rng_bytes") > 0


def test_calls_hmac_sha256(artifacts):
    """The HMAC-DRBG generate path is HMAC-SHA-256 plus the
    backtracking-resistance hmac_drbg_update — both visible in the
    direct call list."""
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_bytes")
    for sym in ("hmac_sha256", "hmac_drbg_update"):
        assert sym in body, f"{sym} not invoked from rng_bytes"


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
    """`rng_bytes(N)` for N ∈ {1, 16, 31, 32, 33, 64, 96, 100} matches
    the HMAC-DRBG oracle (full 32-byte output blocks plus a partial)."""
    got = _qemu_rng(artifacts, count)
    expected = drbg_oracle.drbg_oracle(count)
    assert got == expected, (
        f"count={count}:\n  got:  {got.hex()}\n  want: {expected.hex()}"
    )
