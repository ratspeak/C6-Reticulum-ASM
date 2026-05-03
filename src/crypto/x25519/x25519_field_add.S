# ============================================================================
# @function:    x25519_field_add
# @module:      crypto/x25519
# @inputs:      a0 = out ptr (40 bytes; may alias a1 or a2)
#               a1 = a   ptr (40 bytes)
#               a2 = b   ptr (40 bytes)
# @outputs:     out[i] = a[i] + b[i] for i in 0..9   (pointwise int32 add)
# @clobbers:    t0..t6
# @preserves:   sp, gp, ra, a0..a7, all callee-saved
# @stack:       0
# @cycles:      bounded (~50: 10 unrolled lw/lw/add/sw triples + ret)
# @ct:          required
# @spec:        donna 32-bit / RFC 7748 §5 — pointwise limb add over the
#               radix-2^25.5 representation. No reduction: limbs may
#               grow by one bit; later operations carry-propagate.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_add.saw, proofs/crypto/x25519/x25519_field_add.bsc, proofs/crypto/x25519/x25519_field_add.py
# @tests:       tests/crypto/x25519/test_x25519_field_add.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* x25519_field_add: 10 pointwise int32 adds, fully unrolled. The
 * result is stored to *out with no carry propagation — callers chain
 * adds freely; reduction happens at multiply time (or at pack/unpack).
 *
 * out, a, b may alias. The unrolled form loads a[i] and b[i] into
 * separate temporaries before storing, so in-place is safe. */

        .include "x25519.S"

        .section .text.x25519_field_add, "ax", @progbits
        .global x25519_field_add
        .type   x25519_field_add, @function
x25519_field_add:
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4)(a1)
        lw      t1, (\i*4)(a2)
        add     t0, t0, t1
        sw      t0, (\i*4)(a0)
        .endr
        ret

        .size   x25519_field_add, . - x25519_field_add
