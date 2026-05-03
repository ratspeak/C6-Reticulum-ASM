# ============================================================================
# @function:    x25519_decode_scalar
# @module:      crypto/x25519
# @inputs:      a0 = scalar ptr (32 bytes; modified in place)
# @outputs:     scalar[0]  = original[0]  & 0xF8     (clear low 3 bits)
#               scalar[31] = (original[31] & 0x7F) | 0x40
#                              (clear high bit, set bit 6)
#               scalar[1..30] unchanged
# @clobbers:    t0
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~10: 2 lbu/sb pairs around 3 mask ops)
# @ct:          required
# @spec:        RFC 7748 §5 — decode_scalar25519 clamping
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_decode_scalar.saw, proofs/crypto/x25519/x25519_decode_scalar.py, proofs/crypto/x25519/x25519_decode_scalar.bsc
# @tests:       tests/crypto/x25519/test_x25519_decode_scalar.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* RFC 7748 §5 scalar clamping, applied in place.
 *
 *   k[0]  &= 248       (clear bits 0..2 → result divisible by 8)
 *   k[31] &= 127       (clear high bit)
 *   k[31] |= 64        (set bit 6 → integer ≥ 2^254)
 *
 * Together: clamped scalar is in 2^254 + 8 * {0..2^251 - 1}. */

        .include "x25519.S"

        .section .text.x25519_decode_scalar, "ax", @progbits
        .global x25519_decode_scalar
        .type   x25519_decode_scalar, @function
x25519_decode_scalar:
        lbu     t0, 0(a0)
        andi    t0, t0, 248
        sb      t0, 0(a0)
        lbu     t0, 31(a0)
        andi    t0, t0, 127
        ori     t0, t0, 64
        sb      t0, 31(a0)
        ret

        .size   x25519_decode_scalar, . - x25519_decode_scalar
