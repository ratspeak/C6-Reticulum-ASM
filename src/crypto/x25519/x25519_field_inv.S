# ============================================================================
# @function:    x25519_field_inv
# @module:      crypto/x25519
# @inputs:      a0 = out limbs ptr (40 bytes)
#               a1 = a   limbs ptr (40 bytes)
# @outputs:     out = a^(p_25519 - 2) mod p_25519, in radix-2^25.5 form,
#                     with limbs reduced into nominal width.
# @clobbers:    t0..t6, a2..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       432
# @cycles:      bounded (~265 fsq + 11 fmul × ~1500 each ≈ 4 × 10^5)
# @ct:          required
# @spec:        Fermat: a^(p-2) ≡ a^(-1) (mod p) for a in (Z/pZ)*. The
#               asm follows the curve25519-donna 32-bit `crecip`
#               addition chain — a fixed sequence of field_sq and
#               field_mul calls building intermediate exponents
#               (2^k - 1) for k = 5, 10, 20, 40, 50, 100, 200, 250, then
#               the final ((2^250 - 1) << 5) * a^11 = a^(2^255 - 21) =
#               a^(p_25519 - 2). The chain is data-independent (the
#               control flow depends only on the public exponent
#               p_25519 - 2), so the function is constant-time.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_inv.saw, proofs/crypto/x25519/x25519_field_inv.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_inv.py
#               (Tier C bridge: QEMU pytest drives field_inv on multiple
#               concrete a values; Python verifies the round-trip
#               a · inv(a) ≡ 1 (mod p) using the algebraic-spec-validated
#               field_mul oracle, plus the canonical KAT inv(1) = 1.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* crecip(out, z):
 *
 *   z2     = z^2
 *   z9     = z^9       (= z^8 * z)
 *   z11    = z^11      (= z^9 * z^2)
 *   z2_5_0 = z^31      = a^(2^5 - 1)
 *
 *   For k in {5, 10, 20, 50, 100}:
 *     z2_(2k)_0 = sq^k(z2_k_0) * z2_k_0  // a^(2^(2k) - 1)
 *
 *   Final:  out = sq^5(z2_250_0) * z11 = a^(2^255 - 21) = a^(p - 2).
 *
 * Stack frame (432 bytes, 16-byte aligned):
 *   T0=0, T1=40, Z2=80, Z9=120, Z11=160,
 *   Z2_5_0=200, Z2_10_0=240, Z2_20_0=280, Z2_50_0=320, Z2_100_0=360.
 *   sp+412 = saved ra; sp+416 = saved s0 (z); sp+420 = saved s1 (out).
 */

        .include "x25519.S"

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

        # FSQ_BUF dst src : both stack-relative offsets.
        .macro FSQ_BUF dst, src
        addi    a0, sp, \dst
        addi    a1, sp, \src
        call    x25519_field_sq
        .endm

        # FMUL_BUF dst a b : all stack-relative.
        .macro FMUL_BUF dst, a, b
        addi    a0, sp, \dst
        addi    a1, sp, \a
        addi    a2, sp, \b
        call    x25519_field_mul
        .endm

        # SQUARE_N N, SRC: execute N successive squarings starting from
        # the buffer at offset SRC, ping-ponging between T0 and T1.
        # After the macro, the result is in T0 if N is odd, T1 if N is even.
        .macro SQUARE_N N, SRC
        FSQ_BUF T0, \SRC                        /* 1 square; result in T0 */
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
        FSQ_BUF T1, T0                          /* parity flip; result in T1 */
        .endif
        .endm

        .section .text.x25519_field_inv, "ax", @progbits
        .global x25519_field_inv
        .type   x25519_field_inv, @function
x25519_field_inv:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a1                          /* save z input          */
        mv      s1, a0                          /* save out output       */

        # ---- z^2 → z9 → z11 → z31 = z2_5_0 ----------------------------
        addi    a0, sp, Z2                      /* z2 = z^2              */
        mv      a1, s0
        call    x25519_field_sq
        FSQ_BUF T1, Z2                          /* t1 = z^4              */
        FSQ_BUF T0, T1                          /* t0 = z^8              */
        addi    a0, sp, Z9                      /* z9 = t0 * z = z^9     */
        addi    a1, sp, T0
        mv      a2, s0
        call    x25519_field_mul
        FMUL_BUF Z11, Z9, Z2                    /* z11 = z9 * z2 = z^11  */
        FSQ_BUF T0, Z11                         /* t0 = z^22             */
        FMUL_BUF Z2_5_0, T0, Z9                 /* z2_5_0 = a^(2^5 - 1)  */

        # ---- z2_10_0 = sq^5(z2_5_0) * z2_5_0 -------------------------
        SQUARE_N 5, Z2_5_0                      /* result in T0          */
        FMUL_BUF Z2_10_0, T0, Z2_5_0

        # ---- z2_20_0 = sq^10(z2_10_0) * z2_10_0 ----------------------
        SQUARE_N 10, Z2_10_0                    /* result in T1          */
        FMUL_BUF Z2_20_0, T1, Z2_10_0

        # ---- intermediate t0 = sq^20(z2_20_0) * z2_20_0 = a^(2^40 - 1)
        SQUARE_N 20, Z2_20_0                    /* result in T1          */
        FMUL_BUF T0, T1, Z2_20_0

        # ---- z2_50_0 = sq^10(t0) * z2_10_0 = a^(2^50 - 1) ------------
        SQUARE_N 10, T0                         /* result in T1          */
        FMUL_BUF Z2_50_0, T1, Z2_10_0

        # ---- z2_100_0 = sq^50(z2_50_0) * z2_50_0 ---------------------
        SQUARE_N 50, Z2_50_0                    /* result in T1          */
        FMUL_BUF Z2_100_0, T1, Z2_50_0

        # ---- intermediate t0 = sq^100(z2_100_0) * z2_100_0 = a^(2^200 - 1)
        SQUARE_N 100, Z2_100_0                  /* result in T1          */
        FMUL_BUF T0, T1, Z2_100_0

        # ---- z2_(250)_0 storage piggybacks on T0 here:
        # z2_250_0 = sq^50(t0) * z2_50_0 = a^(2^250 - 1)
        SQUARE_N 50, T0                         /* result in T1          */
        FMUL_BUF T0, T1, Z2_50_0                /* t0 now = a^(2^250 - 1) */

        # ---- final: out = sq^5(t0) * z11 = a^(2^255 - 21) = a^(p - 2)
        SQUARE_N 5, T0                          /* result in T0          */
        mv      a0, s1                          /* dst = caller's out    */
        addi    a1, sp, T0
        addi    a2, sp, Z11
        call    x25519_field_mul

        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   x25519_field_inv, . - x25519_field_inv
