# ============================================================================
# @function:    x25519_field_sq
# @module:      crypto/x25519
# @inputs:      a0 = out limbs ptr (40 bytes; may alias a1)
#               a1 = a   limbs ptr (40 bytes)
# @outputs:     out = (a * a) mod p_25519, in radix-2^25.5 form, with limbs
#                     reduced into nominal width.
# @clobbers:    t0..t6, a2..a7
# @preserves:   sp, gp, ra, a0, a1, all callee-saved
# @stack:       160
# @cycles:      bounded (~1500: same as field_mul; see notes for the
#               future optimised path that halves multiplications)
# @ct:          required
# @spec:        f_sq(a) ≡ f_mul(a, a). Currently implemented as a tail
#               call to x25519_field_mul; this is provably equivalent
#               (decode_limbs(out) = a*a mod p) and avoids duplicating
#               the 100-mul / freduce_degree / freduce_coefficients
#               body. A future optimised version (donna `fsquare` style:
#               55 mul instead of 100, leveraging a[i]*a[j] = a[j]*a[i]
#               for i<j) can replace this body without changing the
#               post-condition.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_sq.saw, proofs/crypto/x25519/x25519_field_sq.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_sq.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

        .include "x25519.S"

        .section .text.x25519_field_sq, "ax", @progbits
        .global x25519_field_sq
        .type   x25519_field_sq, @function
x25519_field_sq:
        mv      a2, a1                  /* b := a (alias)              */
        tail    x25519_field_mul        /* j; ra preserved by callee   */

        .size   x25519_field_sq, . - x25519_field_sq
