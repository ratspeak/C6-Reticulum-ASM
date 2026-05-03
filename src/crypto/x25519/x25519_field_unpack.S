# ============================================================================
# @function:    x25519_field_unpack
# @module:      crypto/x25519
# @inputs:      a0 = out limbs ptr (40 bytes; 10 × int32)
#               a1 = in bytes ptr (32 bytes; little-endian wire form)
# @outputs:     out[i] is the i-th 25 or 26 bit slice of in, per radix
#               2^25.5 (curve25519-donna `fexpand`).
# @clobbers:    t0..t6, a2..a4
# @preserves:   sp, gp, ra, a0, a1, all callee-saved
# @stack:       0
# @cycles:      bounded (~100; 10 × ~10-instruction extractions)
# @ct:          required
# @spec:        donna 32-bit `fexpand` — distributes 256 wire bits across
#               10 limbs at offsets (0,26,51,77,102,128,153,179,204,230)
#               with widths (26,25,26,25,26,25,26,25,26,25). The high
#               bit (255) is dropped because the wire form has 256 bits
#               but the field has 255; callers requiring the RFC 7748
#               u-coordinate high-bit mask wrap this with x25519_decode_u.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_unpack.saw, proofs/crypto/x25519/x25519_field_unpack.py, proofs/crypto/x25519/x25519_field_unpack.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_unpack.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* fexpand: distribute 256 wire bits across 10 radix-2^25.5 limbs.
 *
 * Implementation strategy: byte-by-byte loads (no alignment assumption
 * on the input buffer), assembled into a 32-bit window starting at
 * the limb's source byte offset, shifted right by the source bit
 * offset, and masked. Each of the 10 extractions is unrolled.
 *
 * Limb table:
 *   limb byte  bit  width  mask
 *   0    0     0    26     0x03FFFFFF
 *   1    3     2    25     0x01FFFFFF
 *   2    6     3    26     0x03FFFFFF
 *   3    9     5    25     0x01FFFFFF
 *   4    12    6    26     0x03FFFFFF
 *   5    16    0    25     0x01FFFFFF
 *   6    19    1    26     0x03FFFFFF
 *   7    22    3    25     0x01FFFFFF
 *   8    25    4    26     0x03FFFFFF
 *   9    28    6    25     0x01FFFFFF
 *
 * Mask reuse: a4 = 0x03FFFFFF (26-bit), a3 = 0x01FFFFFF (25-bit).
 * Loaded once at function entry. */

        .include "x25519.S"

        .equ MASK_25,   0x01FFFFFF
        .equ MASK_26,   0x03FFFFFF

        .macro UNPACK_LIMB byte_off, bit_off, width_mask, limb_idx
        lbu     t0, \byte_off(a1)
        lbu     t1, \byte_off+1(a1)
        lbu     t2, \byte_off+2(a1)
        lbu     t3, \byte_off+3(a1)
        slli    t1, t1, 8
        slli    t2, t2, 16
        slli    t3, t3, 24
        or      t0, t0, t1
        or      t0, t0, t2
        or      t0, t0, t3
        srli    t0, t0, \bit_off
        and     t0, t0, \width_mask
        sw      t0, \limb_idx*4(a0)
        .endm

        .section .text.x25519_field_unpack, "ax", @progbits
        .global x25519_field_unpack
        .type   x25519_field_unpack, @function
x25519_field_unpack:
        li      a4, MASK_26
        li      a3, MASK_25

        UNPACK_LIMB 0,  0, a4, 0    /* limb 0: bytes 0..3,  bit 0,  26 */
        UNPACK_LIMB 3,  2, a3, 1    /* limb 1: bytes 3..6,  bit 2,  25 */
        UNPACK_LIMB 6,  3, a4, 2
        UNPACK_LIMB 9,  5, a3, 3
        UNPACK_LIMB 12, 6, a4, 4
        UNPACK_LIMB 16, 0, a3, 5
        UNPACK_LIMB 19, 1, a4, 6
        UNPACK_LIMB 22, 3, a3, 7
        UNPACK_LIMB 25, 4, a4, 8
        UNPACK_LIMB 28, 6, a3, 9

        ret

        .size   x25519_field_unpack, . - x25519_field_unpack
