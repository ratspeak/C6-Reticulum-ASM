"""Static + QEMU smoke tests for `rng_init`.

`rng_init` is HMAC-DRBG-SHA-256 instantiate per NIST SP 800-90A
Rev. 1 §10.1.2.3:
  1. seed_material = entropy_input(32) || nonce(16)   (= rng_entropy(48))
  2. K = 0x00 * 32
  3. V = 0x01 * 32
  4. (K, V) = HMAC_DRBG_Update(seed_material, K, V)
  5. reseed_counter = 1

The TARGET_QEMU_VIRT entropy source is the deterministic-fake
`sha256(SEED || counter_le32)` CSPRNG (see test_rng_bytes.py for the
oracle). This test asserts the post-instantiate state by observing
that the first 32 bytes from a subsequent `rng_bytes(32)` call match
the in-script HMAC-DRBG oracle.
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
    assert build.symbol_address(artifacts.elf, "rng_init") > 0


def test_calls_entropy_and_drbg_update(artifacts):
    """rng_init's body must call rng_entropy (seed gathering) and
    hmac_drbg_update (the §10.1.2.3 step-4 update)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_init")
    for sym in ("rng_entropy", "hmac_drbg_update"):
        assert sym in body, f"{sym} not invoked from rng_init"


def test_seed_symbol_present(artifacts):
    """The DETERMINISTIC_FAKE_RNG marker must remain in the linked
    image so a CI gate can refuse a release build that includes it."""
    assert build.symbol_address(artifacts.elf, "DETERMINISTIC_FAKE_RNG") > 0


def test_drbg_state_symbols_present(artifacts):
    """All three pieces of HMAC-DRBG state are addressable in BSS."""
    for sym in ("hmac_drbg_K", "hmac_drbg_V", "hmac_drbg_reseed_counter"):
        assert build.symbol_address(artifacts.elf, sym) > 0, sym


# ---------- QEMU smoke (asserts the post-condition by observation) ----------

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


def test_first_block_matches_drbg_instantiate(artifacts):
    """After boot and the dispatcher's `rng_init`+`rng_bytes(32)`
    sequence, the first 32 emitted bytes must equal the HMAC-DRBG
    instantiate-then-generate(32) output computed by the Python
    oracle."""
    expected = drbg_oracle.drbg_oracle(32)
    got = _qemu_rng(artifacts, 32)
    assert got == expected, f"\n  got:  {got.hex()}\n  want: {expected.hex()}"
