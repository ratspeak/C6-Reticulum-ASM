# ============================================================================
# @function:    x25519_field_sub
# @module:      crypto/x25519
# @inputs:      a0 = out ptr (40 bytes; may alias a1 or a2)
#               a1 = a   ptr (40 bytes)
#               a2 = b   ptr (40 bytes)
# @outputs:     out[i] = a[i] - b[i] for i in 0..9   (signed int32 sub)
# @clobbers:    t0..t6
# @preserves:   sp, gp, ra, a0..a7, all callee-saved
# @stack:       0
# @cycles:      bounded (~50)
# @ct:          required
# @spec:        donna 32-bit — pointwise signed limb subtraction over
#               the radix-2^25.5 representation. No reduction: limbs
#               may go negative; later operations handle signs.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_sub.saw, proofs/crypto/x25519/x25519_field_sub.py
# @tests:       tests/crypto/x25519/test_x25519_field_sub.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* x25519_field_sub: 10 pointwise int32 subs, fully unrolled. */

        .include "x25519.S"

        .section .text.x25519_field_sub, "ax", @progbits
        .global x25519_field_sub
        .type   x25519_field_sub, @function
x25519_field_sub:
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4)(a1)
        lw      t1, (\i*4)(a2)
        sub     t0, t0, t1
        sw      t0, (\i*4)(a0)
        .endr
        ret

        .size   x25519_field_sub, . - x25519_field_sub
