# ============================================================================
# @function:    ed25519_field_pow_p5d8
# @module:      crypto/ed25519
# @inputs:      a0 = out limbs ptr (40 bytes)
#               a1 = a   limbs ptr (40 bytes)
# @outputs:     out = a^((p_25519 - 5) / 8) mod p_25519
#                   = a^(2^252 - 3)
# @clobbers:    t0..t6, a2..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       432
# @cycles:      bounded (~250 fsq + 8 fmul)
# @ct:          required
# @spec:        Ed25519 field exponentiation used inside the field
#               square-root step of point decompression
#               (RFC 8032 §5.1.3): x = u * v³ * (u * v⁷)^((p-5)/8).
#               Built on the same curve25519-donna `crecip` addition
#               chain as x25519_field_inv, but stopping at
#               sq^2(z2_250_0) * a instead of sq^5(z2_250_0) * z11.
# @verify:      kat-only; the QEMU pytest checks the field identity
#               a^((p-5)/8) for several a values via the
#               point_decompress round-trip a → encoded → decoded → a.
# @tests:       tests/crypto/ed25519/test_ed25519_point_decompress.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame mirrors x25519_field_inv (10 working buffers + saved regs). */

        .include "x25519.S"
        .include "ed25519.S"

        .equ T0,        0
        .equ T1,       40
        .equ Z2,       80
        .equ Z9,      120
        .equ Z11,     160
        .equ Z2_5_0,  200
        .equ Z2_10_0, 240
        .equ Z2_20_0, 280
        .equ Z2_50_0, 320
        .equ Z2_100_0,360
        .equ FRAME,   432
        .equ RA_OFF,  412
        .equ S0_OFF,  416
        .equ S1_OFF,  420

        .macro FSQ_BUF dst, src
        addi    a0, sp, \dst
        addi    a1, sp, \src
        call    x25519_field_sq
        .endm

        .macro FMUL_BUF dst, a, b
        addi    a0, sp, \dst
        addi    a1, sp, \a
        addi    a2, sp, \b
        call    x25519_field_mul
        .endm

        .macro SQUARE_N N, SRC
        FSQ_BUF T0, \SRC
        .if ((\N) & 1) == 1
        .rept ((\N - 1) / 2)
        FSQ_BUF T1, T0
        FSQ_BUF T0, T1
        .endr
        .else
        .rept ((\N - 2) / 2)
        FSQ_BUF T1, T0
        FSQ_BUF T0, T1
        .endr
        FSQ_BUF T1, T0
        .endif
        .endm

        .section .text.ed25519_field_pow_p5d8, "ax", @progbits
        .global ed25519_field_pow_p5d8
        .type   ed25519_field_pow_p5d8, @function
ed25519_field_pow_p5d8:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a1                          /* save a (input)         */
        mv      s1, a0                          /* save out               */

        # Same chain as field_inv up through z2_250_0:
        addi    a0, sp, Z2
        mv      a1, s0
        call    x25519_field_sq                 /* z2 = a^2               */
        FSQ_BUF T1, Z2                          /* t1 = a^4               */
        FSQ_BUF T0, T1                          /* t0 = a^8               */
        addi    a0, sp, Z9
        addi    a1, sp, T0
        mv      a2, s0
        call    x25519_field_mul                /* z9 = a^9               */
        FMUL_BUF Z11, Z9, Z2                    /* z11 = a^11             */
        FSQ_BUF T0, Z11                         /* t0 = a^22              */
        FMUL_BUF Z2_5_0, T0, Z9                 /* z2_5_0 = a^(2^5-1)     */

        SQUARE_N 5, Z2_5_0
        FMUL_BUF Z2_10_0, T0, Z2_5_0

        SQUARE_N 10, Z2_10_0
        FMUL_BUF Z2_20_0, T1, Z2_10_0

        SQUARE_N 20, Z2_20_0
        FMUL_BUF T0, T1, Z2_20_0

        SQUARE_N 10, T0
        FMUL_BUF Z2_50_0, T1, Z2_10_0

        SQUARE_N 50, Z2_50_0
        FMUL_BUF Z2_100_0, T1, Z2_50_0

        SQUARE_N 100, Z2_100_0
        FMUL_BUF T0, T1, Z2_100_0

        SQUARE_N 50, T0
        FMUL_BUF T0, T1, Z2_50_0                /* t0 = a^(2^250 - 1)     */

        # Final 2 squarings + multiply by a (not z11): a^(2^252 - 3).
        FSQ_BUF T1, T0                          /* a^(2^251 - 2)          */
        FSQ_BUF T0, T1                          /* a^(2^252 - 4)          */
        mv      a0, s1
        addi    a1, sp, T0
        mv      a2, s0                          /* * a                    */
        call    x25519_field_mul

        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_field_pow_p5d8, . - ed25519_field_pow_p5d8
