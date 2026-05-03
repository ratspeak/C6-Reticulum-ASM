# ============================================================================
# @function:    ed25519_point_add
# @module:      crypto/ed25519
# @inputs:      a0 = out ptr (160 bytes; X3, Y3, Z3, T3 — 40 bytes each)
#               a1 = P   ptr (160 bytes; X1, Y1, Z1, T1)
#               a2 = Q   ptr (160 bytes; X2, Y2, Z2, T2)
# @outputs:     out = P + Q on edwards25519, in extended twisted-Edwards
#                     coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z,
#                     T = X*Y/Z.
# @clobbers:    t0..t6, a3..a7, s0..s2
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       352
# @cycles:      bounded (≈ 9 field_mul + 6 field_add/sub ≈ 14K)
# @ct:          required
# @spec:        Bernstein-Birkner-Joye-Lange-Peters 2008 dedicated
#               addition law on the twisted Edwards model -x²+y²=1+dx²y²
#               (RFC 8032 §5.1.4 and the IACR ePrint 2008/522
#               formulas). 9 multiplications, 6 add/sub. The "2d"
#               variant is used so the constant `ed25519_2d_limbs`
#               folds the doubling into the multiplication.
# @verify:      proofs/crypto/ed25519/Ed25519Point.cry, proofs/crypto/ed25519/ed25519_point_add.saw
# @tests:       tests/crypto/ed25519/test_ed25519_sign.py
#               (Tier A: SAW + Cryptol prove the canonical d and 2d
#               values, that the published base point lies on the
#               curve, and that the BBJLP add formula satisfies left
#               + right identity, additive inverse (B + (-B) = O), and
#               commutativity (2B + B == B + 2B). Tier C bridge:
#               point_add is exercised transitively in the sign and
#               verify QEMU pytests — every signature production +
#               verification calls scalarmult, which in turn calls
#               point_add for every set bit of the scalar.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (352 bytes, 16-byte aligned):
 *      0..39    A
 *     40..79    B
 *     80..119   C
 *    120..159   D
 *    160..199   E
 *    200..239   F
 *    240..279   G
 *    280..319   H
 *    320..335   pad
 *    336..339   s2
 *    340..343   s1
 *    344..347   s0
 *    348..351   ra
 *
 * Saved regs:  s0 = out, s1 = P, s2 = Q (preserved across field calls)
 *
 * Point layout: X@0, Y@40, Z@80, T@120 (all in 10-limb radix-2^25.5 form).
 */

        .include "x25519.S"
        .include "ed25519.S"

        .equ A_OFF,    0
        .equ B_OFF,   40
        .equ C_OFF,   80
        .equ D_OFF,  120
        .equ E_OFF,  160
        .equ F_OFF,  200
        .equ G_OFF,  240
        .equ H_OFF,  280
        .equ S2_OFF, 336
        .equ S1_OFF, 340
        .equ S0_OFF, 344
        .equ RA_OFF, 348
        .equ FRAME,  352

        # Point field offsets (X, Y, Z, T = 0, 40, 80, 120).
        .equ PT_X, 0
        .equ PT_Y, 40
        .equ PT_Z, 80
        .equ PT_T, 120

        .section .text.ed25519_point_add, "ax", @progbits
        .global ed25519_point_add
        .type   ed25519_point_add, @function
ed25519_point_add:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        mv      s0, a0
        mv      s1, a1
        mv      s2, a2

        # A := (Y1 - X1) * (Y2 - X2)
        addi    a0, sp, A_OFF
        addi    a1, s1, PT_Y
        addi    a2, s1, PT_X
        call    x25519_field_sub
        addi    a0, sp, B_OFF
        addi    a1, s2, PT_Y
        addi    a2, s2, PT_X
        call    x25519_field_sub
        addi    a0, sp, A_OFF
        addi    a1, sp, A_OFF
        addi    a2, sp, B_OFF
        call    x25519_field_mul

        # B := (Y1 + X1) * (Y2 + X2)
        addi    a0, sp, B_OFF
        addi    a1, s1, PT_Y
        addi    a2, s1, PT_X
        call    x25519_field_add
        addi    a0, sp, C_OFF
        addi    a1, s2, PT_Y
        addi    a2, s2, PT_X
        call    x25519_field_add
        addi    a0, sp, B_OFF
        addi    a1, sp, B_OFF
        addi    a2, sp, C_OFF
        call    x25519_field_mul

        # C := T1 * (2d) * T2
        addi    a0, sp, C_OFF
        addi    a1, s1, PT_T
        la      a2, ed25519_2d_limbs
        call    x25519_field_mul
        addi    a0, sp, C_OFF
        addi    a1, sp, C_OFF
        addi    a2, s2, PT_T
        call    x25519_field_mul

        # D := 2 * (Z1 * Z2)
        addi    a0, sp, D_OFF
        addi    a1, s1, PT_Z
        addi    a2, s2, PT_Z
        call    x25519_field_mul
        addi    a0, sp, D_OFF
        addi    a1, sp, D_OFF
        addi    a2, sp, D_OFF
        call    x25519_field_add

        # E := B - A
        addi    a0, sp, E_OFF
        addi    a1, sp, B_OFF
        addi    a2, sp, A_OFF
        call    x25519_field_sub

        # F := D - C
        addi    a0, sp, F_OFF
        addi    a1, sp, D_OFF
        addi    a2, sp, C_OFF
        call    x25519_field_sub

        # G := D + C
        addi    a0, sp, G_OFF
        addi    a1, sp, D_OFF
        addi    a2, sp, C_OFF
        call    x25519_field_add

        # H := B + A
        addi    a0, sp, H_OFF
        addi    a1, sp, B_OFF
        addi    a2, sp, A_OFF
        call    x25519_field_add

        # X3 := E * F
        addi    a0, s0, PT_X
        addi    a1, sp, E_OFF
        addi    a2, sp, F_OFF
        call    x25519_field_mul

        # Y3 := G * H
        addi    a0, s0, PT_Y
        addi    a1, sp, G_OFF
        addi    a2, sp, H_OFF
        call    x25519_field_mul

        # Z3 := F * G
        addi    a0, s0, PT_Z
        addi    a1, sp, F_OFF
        addi    a2, sp, G_OFF
        call    x25519_field_mul

        # T3 := E * H
        addi    a0, s0, PT_T
        addi    a1, sp, E_OFF
        addi    a2, sp, H_OFF
        call    x25519_field_mul

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_point_add, . - ed25519_point_add
