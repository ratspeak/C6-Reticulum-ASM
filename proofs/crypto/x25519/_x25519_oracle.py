"""proofs/crypto/x25519/_x25519_oracle.py

Python reference for X25519 field arithmetic. Mirrors
proofs/crypto/x25519/X25519.cry algebraically; bridges to/from the
asm's 10-limb radix-2^25.5 representation defined in
docs/design/x25519-field.md.
"""
from __future__ import annotations

import struct

P = 2 ** 255 - 19


def limb_weight(i: int) -> int:
    """Weight of limb i in the radix-2^25.5 representation."""
    return 2 ** ((25 * i) + ((i + 1) // 2))


def decode_limbs(limbs: list[int]) -> int:
    """Decode 10 signed int32 limbs to the field integer (mod p)."""
    assert len(limbs) == 10
    n = 0
    for i, l in enumerate(limbs):
        # Sign-extend each int32 limb.
        if l & 0x8000_0000:
            l = l - (1 << 32)
        n += l * limb_weight(i)
    return n % P


def limbs_to_bytes(limbs: list[int]) -> bytes:
    """Pack 10 int32 limbs as 40 little-endian bytes. Accepts limbs as
    either signed (-2^31..2^31-1) or unsigned (0..2^32-1) values; the
    bit pattern stored is identical."""
    return b"".join(struct.pack("<I", l & 0xFFFF_FFFF) for l in limbs)


def bytes_to_limbs(b: bytes) -> list[int]:
    """Unpack 40 little-endian bytes back into a list of 10 unsigned int32."""
    assert len(b) == 40
    return list(struct.unpack("<10I", b))


# ---- field op specs (the algebraic post-conditions) --------------------

def f_add(a: int, b: int) -> int:
    return (a + b) % P


def f_sub(a: int, b: int) -> int:
    return (a - b) % P


def f_mul(a: int, b: int) -> int:
    return (a * b) % P


def f_inv(a: int) -> int:
    return pow(a, P - 2, P)


# ---- self-test ----------------------------------------------------------

if __name__ == "__main__":
    # Round-trip canonical 0.
    assert decode_limbs([0] * 10) == 0
    # Round-trip canonical 7 (placed in limb 0).
    assert decode_limbs([7] + [0] * 9) == 7
    # Pointwise add of two arbitrary limb arrays.
    a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    b = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    pointwise_sum = [(x + y) & 0xFFFF_FFFF for x, y in zip(a, b)]
    assert decode_limbs(pointwise_sum) == f_add(decode_limbs(a), decode_limbs(b))
    # Pointwise sub.
    pointwise_diff = [(x - y) & 0xFFFF_FFFF for x, y in zip(a, b)]
    assert decode_limbs(pointwise_diff) == f_sub(decode_limbs(a), decode_limbs(b))
    print("X25519 oracle self-test PASS")
