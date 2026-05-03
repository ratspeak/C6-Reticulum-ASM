# ============================================================================
# @function:    ed25519_point_double
# @module:      crypto/ed25519
# @inputs:      a0 = out ptr (160 bytes; X3, Y3, Z3, T3)
#               a1 = P   ptr (160 bytes; X1, Y1, Z1, T1)
# @outputs:     out = 2P on edwards25519, in extended coordinates.
# @clobbers:    t0..t6, a3..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       352
# @cycles:      bounded (≈ 4 sq + 3 mul + 5 add/sub ≈ 11K)
# @ct:          required
# @spec:        Bernstein-Birkner-Joye-Lange-Peters 2008 doubling
#               formula on twisted Edwards: 4 squarings + 3
#               multiplications. T1 is not consumed (and the formula
#               is independent of `a` since we use a = -1 with
#               appropriate signs).
# @verify:      proofs/crypto/ed25519/Ed25519Point.cry, proofs/crypto/ed25519/ed25519_point_double.saw
# @tests:       tests/crypto/ed25519/test_ed25519_sign.py
#               (Tier A: SAW + Cryptol prove that the BBJLP doubling
#               formula at the integer-mod-p level matches the BBJLP
#               dedicated-add formula at equal inputs (point_double(B)
#               == point_add(B, B)) and that doubling preserves the
#               identity. The completeness of the dedicated add on
#               edwards25519 is what makes the constant-time scalarmult
#               possible. Tier C bridge: point_double is exercised
#               transitively in the sign and verify QEMU pytests —
#               every scalarmult performs 256 doublings.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Doubling formula (extended twisted Edwards, a = -1):
 *   A = X1²
 *   B = Y1²
 *   C = 2 * Z1²
 *   H = A + B
 *   E = H - (X1 + Y1)²       = -2 * X1 * Y1     (sign matches a = -1)
 *   G = A - B                 = X1² - Y1²
 *   F = C + G
 *   X3 = E * F   Y3 = G * H   T3 = E * H   Z3 = F * G
 *
 * Stack frame (352 bytes, 16-byte aligned):
 *      0..39    A
 *     40..79    B
 *     80..119   C
 *    120..159   H
 *    160..199   E
 *    200..239   G
 *    240..279   F
 *    280..319   tmp     (X1+Y1; squared into E)
 *    320..335   pad
 *    336..343   s0, s1
 *    344..347   pad
 *    348..351   ra
 */

        .include "x25519.S"
        .include "ed25519.S"

        .equ A_OFF,    0
        .equ B_OFF,   40
        .equ C_OFF,   80
        .equ H_OFF,  120
        .equ E_OFF,  160
        .equ G_OFF,  200
        .equ F_OFF,  240
        .equ TMP_OFF,280
        .equ S0_OFF, 336
        .equ S1_OFF, 340
        .equ RA_OFF, 348
        .equ FRAME,  352

        .equ PT_X, 0
        .equ PT_Y, 40
        .equ PT_Z, 80
        .equ PT_T, 120

        .section .text.ed25519_point_double, "ax", @progbits
        .global ed25519_point_double
        .type   ed25519_point_double, @function
ed25519_point_double:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a0                          /* out                    */
        mv      s1, a1                          /* P                      */

        # A := X1²
        addi    a0, sp, A_OFF
        addi    a1, s1, PT_X
        call    x25519_field_sq

        # B := Y1²
        addi    a0, sp, B_OFF
        addi    a1, s1, PT_Y
        call    x25519_field_sq

        # C := 2 * Z1²    (Z1² then add to itself)
        addi    a0, sp, C_OFF
        addi    a1, s1, PT_Z
        call    x25519_field_sq
        addi    a0, sp, C_OFF
        addi    a1, sp, C_OFF
        addi    a2, sp, C_OFF
        call    x25519_field_add

        # H := A + B
        addi    a0, sp, H_OFF
        addi    a1, sp, A_OFF
        addi    a2, sp, B_OFF
        call    x25519_field_add

        # tmp := X1 + Y1 ; tmp := tmp² ; E := H - tmp
        addi    a0, sp, TMP_OFF
        addi    a1, s1, PT_X
        addi    a2, s1, PT_Y
        call    x25519_field_add
        addi    a0, sp, TMP_OFF
        addi    a1, sp, TMP_OFF
        call    x25519_field_sq
        addi    a0, sp, E_OFF
        addi    a1, sp, H_OFF
        addi    a2, sp, TMP_OFF
        call    x25519_field_sub

        # G := A - B
        addi    a0, sp, G_OFF
        addi    a1, sp, A_OFF
        addi    a2, sp, B_OFF
        call    x25519_field_sub

        # F := C + G
        addi    a0, sp, F_OFF
        addi    a1, sp, C_OFF
        addi    a2, sp, G_OFF
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

        # T3 := E * H
        addi    a0, s0, PT_T
        addi    a1, sp, E_OFF
        addi    a2, sp, H_OFF
        call    x25519_field_mul

        # Z3 := F * G
        addi    a0, s0, PT_Z
        addi    a1, sp, F_OFF
        addi    a2, sp, G_OFF
        call    x25519_field_mul

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_point_double, . - ed25519_point_double
