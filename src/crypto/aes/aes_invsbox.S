# ============================================================================
# @function:    aes_invsbox
# @module:      crypto/aes
# @inputs:      a0 = input byte (low 8 bits)
# @outputs:     a0 = AES inverse-S-box(input) (low 8 bits)
# @clobbers:    t0..t6, ra, a1..a7
# @preserves:   sp, gp, s0..s11
# @stack:       16
# @cycles:      ~390 (pre-affine + aes_sbox + post-affine)
# @ct:          required
# @spec:        FIPS 197 §5.3.2 + Saarinen identity
#               iS(x) = A(S(A(x)))   where  A(x) = rol8(x,6) ^ rol8(x,3) ^ rol8(x,1) ^ 0x05
#               (BearSSL src/symcipher/aes_ct.c:br_aes_ct_bitslice_invSbox)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw
# @tests:       tests/crypto/aes/test_aes_invsbox.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES inverse S-box, byte-wise. Implemented as a sandwich: a small affine
 * transform A() bracketing one forward S-box call. The forward S-box is
 * the constant-time Boyar-Peralta circuit in aes_sbox; A() is itself
 * three rotations and four XORs (also constant-time).
 *
 *   iS(x) = A( S( A(x) ) )
 *
 * with  A(x) = rol8(x,6) ^ rol8(x,3) ^ rol8(x,1) ^ 0x05.
 *
 * RV32IMAC has no rotate instruction, so each rol8 is two shifts + or
 * + mask. The 4 NOTs of the bit-sliced BearSSL form collapse to the
 * single XOR with constant 0x05 because pairs of NOTs along the same
 * output XOR cancel (see derivation in test_aes_invsbox.py).
 */

        .include "aes.S"

        .section .text.aes_invsbox, "ax", @progbits
        .global aes_invsbox
        .type   aes_invsbox, @function
aes_invsbox:
        addi    sp, sp, -16
        sw      ra, 12(sp)

        /* --- Pre-affine: a0 = A(a0) --- */
        andi    t0, a0, 0xff            /* clean byte */

        /* rol8(t0, 6) */
        slli    t1, t0, 6
        srli    t2, t0, 2
        or      t1, t1, t2
        andi    t1, t1, 0xff            /* t1 = rol8(input, 6) */

        /* rol8(t0, 3) */
        slli    t2, t0, 3
        srli    t3, t0, 5
        or      t2, t2, t3
        andi    t2, t2, 0xff            /* t2 = rol8(input, 3) */

        /* rol8(t0, 1) */
        slli    t3, t0, 1
        srli    t4, t0, 7
        or      t3, t3, t4
        andi    t3, t3, 0xff            /* t3 = rol8(input, 1) */

        xor     t1, t1, t2
        xor     t1, t1, t3
        xori    a0, t1, 0x05            /* a0 = A(input) */
        andi    a0, a0, 0xff

        call    aes_sbox                /* a0 = S(A(input)) */

        /* --- Post-affine: a0 = A(a0) --- */
        andi    t0, a0, 0xff
        slli    t1, t0, 6
        srli    t2, t0, 2
        or      t1, t1, t2
        andi    t1, t1, 0xff
        slli    t2, t0, 3
        srli    t3, t0, 5
        or      t2, t2, t3
        andi    t2, t2, 0xff
        slli    t3, t0, 1
        srli    t4, t0, 7
        or      t3, t3, t4
        andi    t3, t3, 0xff
        xor     t1, t1, t2
        xor     t1, t1, t3
        xori    a0, t1, 0x05
        andi    a0, a0, 0xff            /* a0 = A(S(A(input))) = iS(input) */

        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   aes_invsbox, . - aes_invsbox
