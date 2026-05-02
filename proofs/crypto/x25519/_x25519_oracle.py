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


# Donna fexpand: split 32 wire bytes across 10 radix-2^25.5 limbs.
# Mirrors src/crypto/x25519/x25519_field_unpack.S.
_LIMB_TABLE = [
    # (byte_offset, bit_offset, width_mask)
    (0,  0, 0x03FFFFFF),
    (3,  2, 0x01FFFFFF),
    (6,  3, 0x03FFFFFF),
    (9,  5, 0x01FFFFFF),
    (12, 6, 0x03FFFFFF),
    (16, 0, 0x01FFFFFF),
    (19, 1, 0x03FFFFFF),
    (22, 3, 0x01FFFFFF),
    (25, 4, 0x03FFFFFF),
    (28, 6, 0x01FFFFFF),
]


def field_unpack_oracle(wire: bytes) -> list[int]:
    """Mirror of x25519_field_unpack: 32 wire bytes -> 10 limbs."""
    assert len(wire) == 32
    out = []
    for byte_off, bit_off, mask in _LIMB_TABLE:
        word = (wire[byte_off]
                | (wire[byte_off + 1] << 8)
                | (wire[byte_off + 2] << 16)
                | (wire[byte_off + 3] << 24))
        out.append((word >> bit_off) & mask)
    return out


def _signed_limb(l: int) -> int:
    """Sign-extend an int32 bit-pattern to a Python int."""
    return l - (1 << 32) if l & 0x8000_0000 else l


def field_mul121665_oracle(in_limbs: list[int]) -> list[int]:
    """Mirror of x25519_field_mul121665: limbwise multiply by 121665 with
    carry-propagation and high-overflow fold back into limb 0 (×19)."""
    assert len(in_limbs) == 10
    scalar = 121665
    accum = 0
    out = [0] * 10
    widths = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)
    masks  = (0x03FFFFFF, 0x01FFFFFF) * 5
    for i in range(10):
        accum += _signed_limb(in_limbs[i]) * scalar
        out[i] = accum & masks[i]
        accum >>= widths[i]
    # Fold the high overflow back into limb 0 with weight 19.
    out[0] += accum * 19
    # One more carry to keep limb 0 in 26 bits.
    c = out[0] >> 26
    out[0] &= 0x03FFFFFF
    out[1] += c
    # Mask all output limbs to 32-bit unsigned representation (since the
    # asm stores signed int32 bit-patterns).
    return [v & 0xFFFF_FFFF for v in out]


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
