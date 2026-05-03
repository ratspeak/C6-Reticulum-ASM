"""Python mirror of the asm HMAC-DRBG-SHA-256 pipeline.

Used by every test that needs to predict the asm RNG output bit-exactly.
Mirrors three pieces of asm:

  * `rng_entropy`   (TARGET_QEMU_VIRT path) — the deterministic-fake
    CSPRNG `sha256(SEED || counter_le32)` that feeds the DRBG.
  * `hmac_drbg_update` — NIST SP 800-90A Rev. 1 §10.1.2.2.
  * `rng_init` + `rng_bytes` — §10.1.2.3 instantiate + §10.1.2.5
    generate, with unconditional per-call backtracking-resistance.

The oracle is not a stand-in for the real DRBG specification — it is
checked against the asm by the QEMU test, and the asm in turn is
checked against the per-primitive Tier A proofs (HMAC-SHA-256 vs
RFC 4231; SHA-256 vs FIPS 180-4). The transitive chain is:

  asm rng_bytes  ==  this oracle  (QEMU pytest)
  this oracle    ==  NIST SP 800-90A  (visual + the Tier A SAW driver
                                       in proofs/crypto/rng/HMACDRBG.cry)
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Tuple

# Matches src/state/rng.S DETERMINISTIC_FAKE_RNG (31 ASCII bytes + 1 null).
SEED = b"DETERMINISTIC_FAKE_RNG_FOR_QEMU\x00"
assert len(SEED) == 32

HMAC_DRBG_SEED_LEN = 48                         # entropy_input(32) + nonce(16)


def entropy(count: int, *, counter_start: int = 0) -> bytes:
    """Mirror of `rng_entropy` on TARGET_QEMU_VIRT."""
    out = b""
    c = counter_start
    while len(out) < count:
        out += hashlib.sha256(SEED + struct.pack("<I", c)).digest()
        c += 1
    return out[:count]


def _hm(k: bytes, m: bytes) -> bytes:
    return hmac.new(k, m, hashlib.sha256).digest()


def drbg_update(K: bytes, V: bytes, data: bytes) -> Tuple[bytes, bytes]:
    """NIST SP 800-90A Rev 1 §10.1.2.2 HMAC_DRBG_Update."""
    K = _hm(K, V + b"\x00" + data)
    V = _hm(K, V)
    if data:
        K = _hm(K, V + b"\x01" + data)
        V = _hm(K, V)
    return K, V


def drbg_instantiate() -> Tuple[bytes, bytes]:
    """Mirror of asm `rng_init` (counter starts at 0 — `rng_init`
    zeroes `rng_counter` before calling `rng_entropy(48)`)."""
    seed_material = entropy(HMAC_DRBG_SEED_LEN, counter_start=0)
    K = b"\x00" * 32
    V = b"\x01" * 32
    K, V = drbg_update(K, V, seed_material)
    return K, V


def drbg_generate(K: bytes, V: bytes, n: int) -> Tuple[bytes, bytes, bytes]:
    """Mirror of asm `rng_bytes(out, n)` — generate then unconditional
    backtracking-resistance update."""
    out = b""
    while len(out) < n:
        V = _hm(K, V)
        out += V
    out = out[:n]
    K, V = drbg_update(K, V, b"")
    return out, K, V


def drbg_oracle(count: int) -> bytes:
    """Single rng_init + rng_bytes(count) — the asm dispatcher's
    behaviour for the 'r'||count[1] frame in src/boot/_main.S
    (.Lrng_kat)."""
    K, V = drbg_instantiate()
    out, _, _ = drbg_generate(K, V, count)
    return out
