# ============================================================================
# @function:    aes_sbox
# @module:      crypto/aes
# @inputs:      a0 = input byte (low 8 bits)
# @outputs:     a0 = AES S-box(input) (low 8 bits; high bits cleared)
# @clobbers:    t0..t6, a1..a7
# @preserves:   sp, gp, ra, s0..s11, a0 high bits not relevant (output)
# @stack:       192
# @cycles:      ~340 (constant; data-oblivious by construction)
# @ct:          required
# @spec:        FIPS 197 §5.1.1 + Boyar-Peralta combinational circuit
#               (Boyar & Peralta, "A new combinational logic minimization
#                technique with applications to cryptology", 2010 —
#                https://eprint.iacr.org/2009/191).
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes_sbox.bsc
# @tests:       tests/crypto/aes/test_aes_sbox.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES forward S-box, byte-wise, computed via the 113-gate Boyar-Peralta
 * combinational circuit. Constant-time by construction: only AND/XOR on
 * single-bit values; no memory access indexed by secret data; no data-
 * dependent branches.
 *
 * The circuit operates on 8 input bits x0..x7 (x0 = MSB, x7 = LSB),
 * produces 8 output bits S0..S7 (S0 = MSB), via:
 *
 *   1. Top linear layer: 23 XORs on x bits → 21 named values y1..y21
 *      (plus two ephemeral t-locals).
 *   2. Non-linear core: 32 ANDs and 24 mid XORs → 18 named values z0..z17
 *      via intermediate t2..t45.
 *   3. Bottom linear layer: 30 XORs (+4 NOTs on bit 0) on z values →
 *      output bits S0..S7.
 *
 * Stack layout (192 bytes):
 *
 *   0(sp)         saved ra
 *   4..32(sp)     saved s0..s7  (then repurposed as bit registers x0..x7,
 *                                then again as output bits S0..S7)
 *   36..116(sp)   y1..y21 in Phase 1+2; reused for t46..t66 in Phase 3
 *   120..188(sp)  z0..z17
 *
 * No s-reg slot beyond s7 is touched, so s8..s11 need not be saved.
 */

        .include "aes.S"

        .equ FSZ,        192
        .equ RA_OFF,       0
        .equ S0_OFF,       4
        .equ S1_OFF,       8
        .equ S2_OFF,      12
        .equ S3_OFF,      16
        .equ S4_OFF,      20
        .equ S5_OFF,      24
        .equ S6_OFF,      28
        .equ S7_OFF,      32

        .equ Y1_OFF,      36
        .equ Y2_OFF,      40
        .equ Y3_OFF,      44
        .equ Y4_OFF,      48
        .equ Y5_OFF,      52
        .equ Y6_OFF,      56
        .equ Y7_OFF,      60
        .equ Y8_OFF,      64
        .equ Y9_OFF,      68
        .equ Y10_OFF,     72
        .equ Y11_OFF,     76
        .equ Y12_OFF,     80
        .equ Y13_OFF,     84
        .equ Y14_OFF,     88
        .equ Y15_OFF,     92
        .equ Y16_OFF,     96
        .equ Y17_OFF,    100
        .equ Y18_OFF,    104
        .equ Y19_OFF,    108
        .equ Y20_OFF,    112
        .equ Y21_OFF,    116

        .equ Z0_OFF,     120
        .equ Z1_OFF,     124
        .equ Z2_OFF,     128
        .equ Z3_OFF,     132
        .equ Z4_OFF,     136
        .equ Z5_OFF,     140
        .equ Z6_OFF,     144
        .equ Z7_OFF,     148
        .equ Z8_OFF,     152
        .equ Z9_OFF,     156
        .equ Z10_OFF,    160
        .equ Z11_OFF,    164
        .equ Z12_OFF,    168
        .equ Z13_OFF,    172
        .equ Z14_OFF,    176
        .equ Z15_OFF,    180
        .equ Z16_OFF,    184
        .equ Z17_OFF,    188

        /* Phase-3 aliases for the y stack area. T46..T66 = 21 values. */
        .equ T46_OFF,     36
        .equ T47_OFF,     40
        .equ T48_OFF,     44
        .equ T49_OFF,     48
        .equ T50_OFF,     52
        .equ T51_OFF,     56
        .equ T52_OFF,     60
        .equ T53_OFF,     64
        .equ T54_OFF,     68
        .equ T55_OFF,     72
        .equ T56_OFF,     76
        .equ T57_OFF,     80
        .equ T58_OFF,     84
        .equ T59_OFF,     88
        .equ T60_OFF,     92
        .equ T61_OFF,     96
        .equ T62_OFF,    100
        .equ T63_OFF,    104
        .equ T64_OFF,    108
        .equ T65_OFF,    112
        .equ T66_OFF,    116

        .section .text.aes_sbox, "ax", @progbits
        .global aes_sbox
        .type   aes_sbox, @function
aes_sbox:
        addi    sp, sp, -FSZ
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        sw      s5, S5_OFF(sp)
        sw      s6, S6_OFF(sp)
        sw      s7, S7_OFF(sp)

        /* Extract 8 input bits.  s0=x0=bit7 (MSB), s7=x7=bit0 (LSB). */
        srli    s0, a0, 7
        andi    s0, s0, 1
        srli    s1, a0, 6
        andi    s1, s1, 1
        srli    s2, a0, 5
        andi    s2, s2, 1
        srli    s3, a0, 4
        andi    s3, s3, 1
        srli    s4, a0, 3
        andi    s4, s4, 1
        srli    s5, a0, 2
        andi    s5, s5, 1
        srli    s6, a0, 1
        andi    s6, s6, 1
        andi    s7, a0, 1

        /* ============================================================== */
        /* Phase 1: top linear (23 XORs producing y1..y21)                */
        /* ============================================================== */

        /* y14 = x3 ^ x5 */
        xor     t0, s3, s5
        sw      t0, Y14_OFF(sp)

        /* y13 = x0 ^ x6 -- a1 keeps it for y12, y21 */
        xor     a1, s0, s6
        sw      a1, Y13_OFF(sp)

        /* y9 = x0 ^ x3 -- a2 keeps it for y11 */
        xor     a2, s0, s3
        sw      a2, Y9_OFF(sp)

        /* y8 = x0 ^ x5 -- a3 keeps it for y3, y19 */
        xor     a3, s0, s5
        sw      a3, Y8_OFF(sp)

        /* t0_local = x1 ^ x2 -- a4 keeps it for y1, y10, y16 (ephemeral, no spill) */
        xor     a4, s1, s2

        /* y1 = t0_local ^ x7 -- a5 keeps it for y4, y2, y5 */
        xor     a5, a4, s7
        sw      a5, Y1_OFF(sp)

        /* y4 = y1 ^ x3 */
        xor     t0, a5, s3
        sw      t0, Y4_OFF(sp)

        /* y12 = y13 ^ y14 -- a6 keeps it for the t1_local computation */
        lw      t0, Y14_OFF(sp)
        xor     a6, a1, t0
        sw      a6, Y12_OFF(sp)

        /* y2 = y1 ^ x0 */
        xor     t0, a5, s0
        sw      t0, Y2_OFF(sp)

        /* y5 = y1 ^ x6 -- a7 keeps it for y3 */
        xor     a7, a5, s6
        sw      a7, Y5_OFF(sp)

        /* y3 = y5 ^ y8  (a7 = y5, a3 = y8) */
        xor     t0, a7, a3
        sw      t0, Y3_OFF(sp)

        /* t1_local = x4 ^ y12 -- ephemeral, used for y15 and y20 */
        xor     t1, s4, a6

        /* y15 = t1_local ^ x5 -- a6 reused (y12 dead) for y6, y10 */
        xor     a6, t1, s5
        sw      a6, Y15_OFF(sp)

        /* y20 = t1_local ^ x1 -- a7 reused (y5 dead) for y11 */
        xor     a7, t1, s1
        sw      a7, Y20_OFF(sp)

        /* y6 = y15 ^ x7 */
        xor     t0, a6, s7
        sw      t0, Y6_OFF(sp)

        /* y10 = y15 ^ t0_local  (a6 = y15, a4 = t0_local) -- a6 reused for y17, y19 */
        xor     a6, a6, a4
        sw      a6, Y10_OFF(sp)

        /* y11 = y20 ^ y9  (a7 = y20, a2 = y9) -- a7 reused for y7, y17, y16 */
        xor     a7, a7, a2
        sw      a7, Y11_OFF(sp)

        /* y7 = x7 ^ y11 */
        xor     t0, s7, a7
        sw      t0, Y7_OFF(sp)

        /* y17 = y10 ^ y11  (a6 = y10, a7 = y11) */
        xor     t0, a6, a7
        sw      t0, Y17_OFF(sp)

        /* y19 = y10 ^ y8  (a6 = y10, a3 = y8) */
        xor     t0, a6, a3
        sw      t0, Y19_OFF(sp)

        /* y16 = t0_local ^ y11  (a4 = t0_local, a7 = y11) -- a6 reused for y21, y18 */
        xor     a6, a4, a7
        sw      a6, Y16_OFF(sp)

        /* y21 = y13 ^ y16  (a1 = y13, a6 = y16) */
        xor     t0, a1, a6
        sw      t0, Y21_OFF(sp)

        /* y18 = x0 ^ y16  (s0 = x0, a6 = y16) */
        xor     t0, s0, a6
        sw      t0, Y18_OFF(sp)

        /* ============================================================== */
        /* Phase 2: non-linear core. 32 ANDs and 24 mid XORs producing 18 */
        /* z values via t2..t45. Nine long-lived t values live across the */
        /* z computation (a1..a7 + t0 + t1).                              */
        /* ============================================================== */

        /* BP-t2 = y12 & y15 */
        lw      t0, Y12_OFF(sp)
        lw      t1, Y15_OFF(sp)
        and     a1, t0, t1                  /* a1 holds BP-t2 */

        /* BP-t3 = y3 & y6  → t0 (transient) */
        lw      t1, Y3_OFF(sp)
        lw      t2, Y6_OFF(sp)
        and     t0, t1, t2

        /* BP-t4 = BP-t3 ^ BP-t2 (used by t17) */
        xor     t0, t0, a1                  /* t0 holds BP-t4 */

        /* BP-t5 = y4 & x7 */
        lw      t1, Y4_OFF(sp)
        and     t1, t1, s7                  /* t1 holds BP-t5 (transient) */

        /* BP-t6 = BP-t5 ^ BP-t2 */
        xor     t1, t1, a1                  /* t1 holds BP-t6; a1 (BP-t2) freed */

        /* BP-t7 = y13 & y16 */
        lw      t2, Y13_OFF(sp)
        lw      t3, Y16_OFF(sp)
        and     a1, t2, t3                  /* a1 holds BP-t7 */

        /* BP-t8 = y5 & y1 */
        lw      t2, Y5_OFF(sp)
        lw      t3, Y1_OFF(sp)
        and     t2, t2, t3                  /* t2 holds BP-t8 (transient) */

        /* BP-t9 = BP-t8 ^ BP-t7 */
        xor     t2, t2, a1                  /* t2 holds BP-t9 */

        /* BP-t10 = y2 & y7 */
        lw      t3, Y2_OFF(sp)
        lw      t4, Y7_OFF(sp)
        and     t3, t3, t4                  /* t3 holds BP-t10 (transient) */

        /* BP-t11 = BP-t10 ^ BP-t7 */
        xor     t3, t3, a1                  /* t3 holds BP-t11; a1 (BP-t7) freed */

        /* BP-t12 = y9 & y11 */
        lw      t4, Y9_OFF(sp)
        lw      t5, Y11_OFF(sp)
        and     a1, t4, t5                  /* a1 holds BP-t12 */

        /* BP-t13 = y14 & y17 */
        lw      t4, Y14_OFF(sp)
        lw      t5, Y17_OFF(sp)
        and     t4, t4, t5                  /* t4 holds BP-t13 (transient) */

        /* BP-t14 = BP-t13 ^ BP-t12 -- a2 keeps it for t17, t19 */
        xor     a2, t4, a1                  /* a2 holds BP-t14 */

        /* BP-t15 = y8 & y10 */
        lw      t4, Y8_OFF(sp)
        lw      t5, Y10_OFF(sp)
        and     t4, t4, t5                  /* t4 holds BP-t15 (transient) */

        /* BP-t16 = BP-t15 ^ BP-t12 -- a3 keeps it for t18, t20 */
        xor     a3, t4, a1                  /* a3 holds BP-t16; a1 (BP-t12) freed */

        /* BP-t17 = BP-t4 ^ BP-t14 */
        xor     t0, t0, a2                  /* t0 holds BP-t17 */

        /* BP-t18 = BP-t6 ^ BP-t16 */
        xor     t1, t1, a3                  /* t1 holds BP-t18 */

        /* BP-t19 = BP-t9 ^ BP-t14 */
        xor     t2, t2, a2                  /* t2 holds BP-t19 */

        /* BP-t20 = BP-t11 ^ BP-t16 */
        xor     t3, t3, a3                  /* t3 holds BP-t20; a2, a3 freed */

        /* BP-t21 = BP-t17 ^ y20 */
        lw      t4, Y20_OFF(sp)
        xor     t0, t0, t4                  /* t0 = BP-t21 */

        /* BP-t22 = BP-t18 ^ y19 */
        lw      t4, Y19_OFF(sp)
        xor     t1, t1, t4                  /* t1 = BP-t22 */

        /* BP-t23 = BP-t19 ^ y21 */
        lw      t4, Y21_OFF(sp)
        xor     t2, t2, t4                  /* t2 = BP-t23 */

        /* BP-t24 = BP-t20 ^ y18 */
        lw      t4, Y18_OFF(sp)
        xor     t3, t3, t4                  /* t3 = BP-t24 */

        /* === Inner core: t25..t45 === */

        /* BP-t25 = BP-t21 ^ BP-t22 */
        xor     t4, t0, t1                  /* t4 = BP-t25 */

        /* BP-t26 = BP-t21 & BP-t23 */
        and     t5, t0, t2                  /* t5 = BP-t26 */
        /* BP-t21 (t0) freed */

        /* BP-t27 = BP-t24 ^ BP-t26 */
        xor     t6, t3, t5                  /* t6 = BP-t27 */

        /* BP-t28 = BP-t25 & BP-t27 */
        and     t0, t4, t6                  /* t0 = BP-t28 */

        /* BP-t29 = BP-t28 ^ BP-t22 -- a1 long-lived */
        xor     a1, t0, t1                  /* a1 = BP-t29 (used by t39, t42, t43, z5, z14) */

        /* BP-t30 = BP-t23 ^ BP-t24 */
        xor     t0, t2, t3                  /* t0 = BP-t30 */

        /* BP-t31 = BP-t22 ^ BP-t26 */
        xor     t1, t1, t5                  /* t1 = BP-t31; BP-t22 freed; BP-t26 (t5) freed */

        /* BP-t32 = BP-t31 & BP-t30 */
        and     t0, t1, t0                  /* t0 = BP-t32 */

        /* BP-t33 = BP-t32 ^ BP-t24 -- a2 long-lived */
        xor     a2, t0, t3                  /* a2 = BP-t33 (used by t34, t35, t42, t44, z2, z11) */

        /* BP-t34 = BP-t23 ^ BP-t33 */
        xor     t0, t2, a2                  /* t0 = BP-t34 (used by t37) */
        /* BP-t23 (t2) freed */

        /* BP-t35 = BP-t27 ^ BP-t33 */
        xor     t1, t6, a2                  /* t1 = BP-t35 (used by t36) */

        /* BP-t36 = BP-t24 & BP-t35 */
        and     t2, t3, t1                  /* t2 = BP-t36 (used by t37, t38) */
        /* BP-t24 (t3) freed; BP-t35 (t1) freed */

        /* BP-t37 = BP-t36 ^ BP-t34 -- a3 long-lived */
        xor     a3, t2, t0                  /* a3 = BP-t37 (used by t41, t44, z1, z10) */
        /* BP-t34 (t0) freed */

        /* BP-t38 = BP-t27 ^ BP-t36 */
        xor     t0, t6, t2                  /* t0 = BP-t38 */
        /* BP-t27 (t6) freed; BP-t36 (t2) freed */

        /* BP-t39 = BP-t29 & BP-t38 */
        and     t1, a1, t0                  /* t1 = BP-t39 */
        /* BP-t38 (t0) freed */

        /* BP-t40 = BP-t25 ^ BP-t39 -- a4 long-lived */
        xor     a4, t4, t1                  /* a4 = BP-t40 (used by t41, t43, z4, z13) */
        /* BP-t25 (t4) freed; BP-t39 (t1) freed */

        /* BP-t41 = BP-t40 ^ BP-t37 -- a5 long-lived */
        xor     a5, a4, a3                  /* a5 = BP-t41 (used by t45, z8, z17) */

        /* BP-t42 = BP-t29 ^ BP-t33 -- a6 long-lived */
        xor     a6, a1, a2                  /* a6 = BP-t42 (used by t45, z6, z15) */

        /* BP-t43 = BP-t29 ^ BP-t40 -- a7 long-lived */
        xor     a7, a1, a4                  /* a7 = BP-t43 (used by z3, z12) */

        /* BP-t44 = BP-t33 ^ BP-t37 -- t0 long-lived */
        xor     t0, a2, a3                  /* t0 = BP-t44 (used by z0, z9) */

        /* BP-t45 = BP-t42 ^ BP-t41 -- t1 long-lived */
        xor     t1, a6, a5                  /* t1 = BP-t45 (used by z7, z16) */

        /* === z computation: 18 ANDs producing z0..z17 === */
        /* Long-lived t-values: a1=t29, a2=t33, a3=t37, a4=t40, a5=t41,
         * a6=t42, a7=t43, t0=t44, t1=t45 */

        /* z0 = t44 & y15 */
        lw      t2, Y15_OFF(sp)
        and     t2, t2, t0
        sw      t2, Z0_OFF(sp)
        /* z1 = t37 & y6 */
        lw      t2, Y6_OFF(sp)
        and     t2, t2, a3
        sw      t2, Z1_OFF(sp)
        /* z2 = t33 & x7 (s7 = x7) */
        and     t2, s7, a2
        sw      t2, Z2_OFF(sp)
        /* z3 = t43 & y16 */
        lw      t2, Y16_OFF(sp)
        and     t2, t2, a7
        sw      t2, Z3_OFF(sp)
        /* z4 = t40 & y1 */
        lw      t2, Y1_OFF(sp)
        and     t2, t2, a4
        sw      t2, Z4_OFF(sp)
        /* z5 = t29 & y7 */
        lw      t2, Y7_OFF(sp)
        and     t2, t2, a1
        sw      t2, Z5_OFF(sp)
        /* z6 = t42 & y11 */
        lw      t2, Y11_OFF(sp)
        and     t2, t2, a6
        sw      t2, Z6_OFF(sp)
        /* z7 = t45 & y17 */
        lw      t2, Y17_OFF(sp)
        and     t2, t2, t1
        sw      t2, Z7_OFF(sp)
        /* z8 = t41 & y10 */
        lw      t2, Y10_OFF(sp)
        and     t2, t2, a5
        sw      t2, Z8_OFF(sp)
        /* z9 = t44 & y12 */
        lw      t2, Y12_OFF(sp)
        and     t2, t2, t0
        sw      t2, Z9_OFF(sp)
        /* z10 = t37 & y3 */
        lw      t2, Y3_OFF(sp)
        and     t2, t2, a3
        sw      t2, Z10_OFF(sp)
        /* z11 = t33 & y4 */
        lw      t2, Y4_OFF(sp)
        and     t2, t2, a2
        sw      t2, Z11_OFF(sp)
        /* z12 = t43 & y13 */
        lw      t2, Y13_OFF(sp)
        and     t2, t2, a7
        sw      t2, Z12_OFF(sp)
        /* z13 = t40 & y5 */
        lw      t2, Y5_OFF(sp)
        and     t2, t2, a4
        sw      t2, Z13_OFF(sp)
        /* z14 = t29 & y2 */
        lw      t2, Y2_OFF(sp)
        and     t2, t2, a1
        sw      t2, Z14_OFF(sp)
        /* z15 = t42 & y9 */
        lw      t2, Y9_OFF(sp)
        and     t2, t2, a6
        sw      t2, Z15_OFF(sp)
        /* z16 = t45 & y14 */
        lw      t2, Y14_OFF(sp)
        and     t2, t2, t1
        sw      t2, Z16_OFF(sp)
        /* z17 = t41 & y8 */
        lw      t2, Y8_OFF(sp)
        and     t2, t2, a5
        sw      t2, Z17_OFF(sp)

        /* ============================================================== */
        /* Phase 3: bottom linear. 30 XORs (+4 NOTs on bit 0). The y       */
        /* stack area is reused for t46..t66 (21 values). t67 lives in a  */
        /* register.                                                       */
        /* ============================================================== */

        /* t46 = z15 ^ z16 */
        lw      t0, Z15_OFF(sp)
        lw      t1, Z16_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T46_OFF(sp)

        /* t47 = z10 ^ z11 */
        lw      t0, Z10_OFF(sp)
        lw      t1, Z11_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T47_OFF(sp)

        /* t48 = z5 ^ z13 */
        lw      t0, Z5_OFF(sp)
        lw      t1, Z13_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T48_OFF(sp)

        /* t49 = z9 ^ z10 */
        lw      t0, Z9_OFF(sp)
        lw      t1, Z10_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T49_OFF(sp)

        /* t50 = z2 ^ z12 */
        lw      t0, Z2_OFF(sp)
        lw      t1, Z12_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T50_OFF(sp)

        /* t51 = z2 ^ z5 */
        lw      t0, Z2_OFF(sp)
        lw      t1, Z5_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T51_OFF(sp)

        /* t52 = z7 ^ z8 */
        lw      t0, Z7_OFF(sp)
        lw      t1, Z8_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T52_OFF(sp)

        /* t53 = z0 ^ z3 */
        lw      t0, Z0_OFF(sp)
        lw      t1, Z3_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T53_OFF(sp)

        /* t54 = z6 ^ z7 */
        lw      t0, Z6_OFF(sp)
        lw      t1, Z7_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T54_OFF(sp)

        /* t55 = z16 ^ z17 */
        lw      t0, Z16_OFF(sp)
        lw      t1, Z17_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T55_OFF(sp)

        /* t56 = z12 ^ t48 */
        lw      t0, Z12_OFF(sp)
        lw      t1, T48_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T56_OFF(sp)

        /* t57 = t50 ^ t53 */
        lw      t0, T50_OFF(sp)
        lw      t1, T53_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T57_OFF(sp)

        /* t58 = z4 ^ t46 */
        lw      t0, Z4_OFF(sp)
        lw      t1, T46_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T58_OFF(sp)

        /* t59 = z3 ^ t54 */
        lw      t0, Z3_OFF(sp)
        lw      t1, T54_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T59_OFF(sp)

        /* t60 = t46 ^ t57 */
        lw      t0, T46_OFF(sp)
        lw      t1, T57_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T60_OFF(sp)

        /* t61 = z14 ^ t57 */
        lw      t0, Z14_OFF(sp)
        lw      t1, T57_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T61_OFF(sp)

        /* t62 = t52 ^ t58 */
        lw      t0, T52_OFF(sp)
        lw      t1, T58_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T62_OFF(sp)

        /* t63 = t49 ^ t58 */
        lw      t0, T49_OFF(sp)
        lw      t1, T58_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T63_OFF(sp)

        /* t64 = z4 ^ t59 */
        lw      t0, Z4_OFF(sp)
        lw      t1, T59_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T64_OFF(sp)

        /* t65 = t61 ^ t62 */
        lw      t0, T61_OFF(sp)
        lw      t1, T62_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T65_OFF(sp)

        /* t66 = z1 ^ t63 */
        lw      t0, Z1_OFF(sp)
        lw      t1, T63_OFF(sp)
        xor     t0, t0, t1
        sw      t0, T66_OFF(sp)

        /* === Output bits S0..S7 placed back into s0..s7 (the originals  */
        /* are restored from saved slots in the epilogue).                */

        /* S0 = t59 ^ t63 */
        lw      t0, T59_OFF(sp)
        lw      t1, T63_OFF(sp)
        xor     s0, t0, t1

        /* S6 = t56 ^ ~t62  (bit-0 NOT via xori imm=1) */
        lw      t0, T56_OFF(sp)
        lw      t1, T62_OFF(sp)
        xori    t1, t1, 1
        xor     s6, t0, t1

        /* S7 = t48 ^ ~t60 */
        lw      t0, T48_OFF(sp)
        lw      t1, T60_OFF(sp)
        xori    t1, t1, 1
        xor     s7, t0, t1

        /* t67 = t64 ^ t65  (kept in t0; only used by S2) */
        lw      t0, T64_OFF(sp)
        lw      t1, T65_OFF(sp)
        xor     t0, t0, t1

        /* S2 = t55 ^ ~t67 */
        lw      t1, T55_OFF(sp)
        xori    t0, t0, 1
        xor     s2, t1, t0

        /* S3 = t53 ^ t66 */
        lw      t0, T53_OFF(sp)
        lw      t1, T66_OFF(sp)
        xor     s3, t0, t1

        /* S4 = t51 ^ t66 */
        lw      t0, T51_OFF(sp)
        lw      t1, T66_OFF(sp)
        xor     s4, t0, t1

        /* S5 = t47 ^ t65 */
        lw      t0, T47_OFF(sp)
        lw      t1, T65_OFF(sp)
        xor     s5, t0, t1

        /* S1 = t64 ^ ~S3 */
        lw      t0, T64_OFF(sp)
        xori    t1, s3, 1
        xor     s1, t0, t1

        /* ============================================================== */
        /* Pack S0..S7 into output byte (S0 = MSB).                       */
        /* ============================================================== */
        slli    t0, s0, 7
        slli    t1, s1, 6
        or      t0, t0, t1
        slli    t1, s2, 5
        or      t0, t0, t1
        slli    t1, s3, 4
        or      t0, t0, t1
        slli    t1, s4, 3
        or      t0, t0, t1
        slli    t1, s5, 2
        or      t0, t0, t1
        slli    t1, s6, 1
        or      t0, t0, t1
        or      a0, t0, s7

        /* Restore saved s-regs and return. */
        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        lw      s5, S5_OFF(sp)
        lw      s6, S6_OFF(sp)
        lw      s7, S7_OFF(sp)
        addi    sp, sp, FSZ
        ret

        .size   aes_sbox, . - aes_sbox
