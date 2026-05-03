# ============================================================================
# @function:    ed25519_point_decompress
# @module:      crypto/ed25519
# @inputs:      a0 = out_point ptr (160 bytes; X, Y, Z, T extended coords)
#               a1 = in_bytes ptr  (32 bytes; encoded edwards point)
# @outputs:     a0 (return value): 0 on success, 1 on invalid point.
#               If valid: out_point = decoded point with Z = 1, T = X*Y.
# @clobbers:    t0..t6, a2..a7, s0..s4
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       384
# @cycles:      bounded (~field_pow_p5d8 + ~10 field_mul)
# @ct:          required (control flow only depends on the public
#                 encoded bytes; rejection of invalid points is the
#                 only data-dependent branch, and that's a public
#                 outcome)
# @spec:        RFC 8032 §5.1.3 — point decoding via field square root.
#                 1. y := LE-decode(in_bytes[0..30] | (in_bytes[31] & 0x7F))
#                 2. sign := (in_bytes[31] >> 7) & 1
#                 3. u := y² - 1
#                 4. v := d * y² + 1
#                 5. cand := u * v³ * (u * v⁷)^((p-5)/8)
#                 6. if v * cand² == u: x = cand
#                    elif v * cand² == -u: x = cand * sqrt(-1)
#                    else: invalid (return 1)
#                 7. if x_LSB != sign: x = -x
#                 8. write extended (X, Y, Z=1, T=X*Y)
# @verify:      kat-only; QEMU pytest exercises decompress on
#                 - the base point B (RFC 8032 §5.1.5)
#                 - several random pyca/cryptography-derived public keys
#                 - confirms compress(decompress(P)) == P round-trip
# @tests:       tests/crypto/ed25519/test_ed25519_point_decompress.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (384 bytes, 16-byte aligned):
 *      0..39    Y_BUF      (recovered y limbs)
 *     40..79    U_BUF      (y² - 1)
 *     80..119   V_BUF      (d*y² + 1)
 *    120..159   T1_BUF     (scratch: y², v³, vxx, ...)
 *    160..199   T2_BUF     (scratch: v⁷, uv⁷, pow, ...)
 *    200..239   X_BUF      (candidate x — finalised)
 *    240..279   X_SQ_BUF   (x²)
 *    280..319   T3_BUF     (scratch)
 *    320..335   pad
 *    336..339   s4 (return-code accumulator)
 *    340..343   s3 (scratch)
 *    344..347   s2 (sign bit)
 *    348..351   s1 (in_bytes ptr)
 *    352..355   s0 (out_point ptr)
 *    356..359   ra
 *    360..383   pad
 *
 * Saved regs:
 *   s0 = out_point
 *   s1 = in_bytes
 *   s2 = sign_bit (0 or 1)
 *   s3 = scratch
 *   s4 = return value (0 = ok, 1 = invalid)
 */

        .include "x25519.S"
        .include "ed25519.S"

        .equ Y_BUF,      0
        .equ U_BUF,     40
        .equ V_BUF,     80
        .equ T1_BUF,   120
        .equ T2_BUF,   160
        .equ X_BUF,    200
        .equ X_SQ_BUF, 240
        .equ T3_BUF,   280
        .equ S4_OFF,   336
        .equ S3_OFF,   340
        .equ S2_OFF,   344
        .equ S1_OFF,   348
        .equ S0_OFF,   352
        .equ RA_OFF,   356
        .equ FRAME,    384

        .equ PT_X, 0
        .equ PT_Y, 40
        .equ PT_Z, 80
        .equ PT_T, 120

        # Helper: check whether a 10-limb field element decodes to 0
        # (mod p). Returns t0 = 1 if zero, else 0. Pack to canonical
        # 32 bytes and OR all of them together.
        # Uses sp + T3_BUF as a 32-byte scratch (pack output goes there).
        .macro IS_FIELD_ZERO src_off, result
        addi    a0, sp, T3_BUF
        addi    a1, sp, \src_off
        call    x25519_field_pack
        # OR all 32 bytes into t0; t0 == 0 ⇔ field element was 0 mod p.
        addi    t1, sp, T3_BUF
        lw      t0, 0(t1)
        lw      t2, 4(t1)
        or      t0, t0, t2
        lw      t2, 8(t1)
        or      t0, t0, t2
        lw      t2, 12(t1)
        or      t0, t0, t2
        lw      t2, 16(t1)
        or      t0, t0, t2
        lw      t2, 20(t1)
        or      t0, t0, t2
        lw      t2, 24(t1)
        or      t0, t0, t2
        lw      t2, 28(t1)
        or      t0, t0, t2
        # \result = (t0 == 0) ? 1 : 0
        sltiu   \result, t0, 1
        .endm

        .section .text.ed25519_point_decompress, "ax", @progbits
        .global ed25519_point_decompress
        .type   ed25519_point_decompress, @function
ed25519_point_decompress:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        mv      s0, a0
        mv      s1, a1

        # Extract sign bit from in_bytes[31] before unpacking (which
        # would mask it out).
        lbu     t0, 31(s1)
        srli    s2, t0, 7                       /* sign bit              */

        # Y_BUF := field_unpack(in_bytes)  (drops bit 255 implicitly)
        addi    a0, sp, Y_BUF
        mv      a1, s1
        call    x25519_field_unpack

        # T1_BUF := y²
        addi    a0, sp, T1_BUF
        addi    a1, sp, Y_BUF
        call    x25519_field_sq

        # U_BUF := T1_BUF - 1   ;  V_BUF := d * T1_BUF + 1
        # Build "1" as a stack literal in T2_BUF[0..40] (=[1, 0, ..., 0])
        li      t0, 1
        sw      t0, T2_BUF(sp)
        .irp i, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, (\i + T2_BUF)(sp)
        .endr
        addi    a0, sp, U_BUF
        addi    a1, sp, T1_BUF
        addi    a2, sp, T2_BUF
        call    x25519_field_sub

        # V_BUF := d * y² + 1
        addi    a0, sp, V_BUF
        addi    a1, sp, T1_BUF
        la      a2, ed25519_d_limbs
        call    x25519_field_mul
        # T2_BUF still holds [1, 0, ...]; reuse:
        addi    a0, sp, V_BUF
        addi    a1, sp, V_BUF
        addi    a2, sp, T2_BUF
        call    x25519_field_add

        # T1_BUF := v³ = v² * v
        addi    a0, sp, T1_BUF
        addi    a1, sp, V_BUF
        call    x25519_field_sq
        addi    a0, sp, T1_BUF
        addi    a1, sp, T1_BUF
        addi    a2, sp, V_BUF
        call    x25519_field_mul

        # T2_BUF := v⁷ = v³ * v³ * v = (v³)² * v
        addi    a0, sp, T2_BUF
        addi    a1, sp, T1_BUF
        call    x25519_field_sq
        addi    a0, sp, T2_BUF
        addi    a1, sp, T2_BUF
        addi    a2, sp, V_BUF
        call    x25519_field_mul

        # T2_BUF := u * v⁷
        addi    a0, sp, T2_BUF
        addi    a1, sp, U_BUF
        addi    a2, sp, T2_BUF
        call    x25519_field_mul

        # T2_BUF := T2_BUF^((p-5)/8)
        addi    a0, sp, T2_BUF
        addi    a1, sp, T2_BUF
        call    ed25519_field_pow_p5d8

        # X_BUF := u * v³ * pow = U_BUF * T1_BUF * T2_BUF
        addi    a0, sp, X_BUF
        addi    a1, sp, U_BUF
        addi    a2, sp, T1_BUF
        call    x25519_field_mul
        addi    a0, sp, X_BUF
        addi    a1, sp, X_BUF
        addi    a2, sp, T2_BUF
        call    x25519_field_mul

        # X_SQ_BUF := x²
        addi    a0, sp, X_SQ_BUF
        addi    a1, sp, X_BUF
        call    x25519_field_sq

        # T1_BUF := v * x² = vxx
        addi    a0, sp, T1_BUF
        addi    a1, sp, V_BUF
        addi    a2, sp, X_SQ_BUF
        call    x25519_field_mul

        # T2_BUF := vxx - u  (test for ==)
        addi    a0, sp, T2_BUF
        addi    a1, sp, T1_BUF
        addi    a2, sp, U_BUF
        call    x25519_field_sub
        IS_FIELD_ZERO T2_BUF, s3                /* s3 = (vxx == u)?      */

        # If s3 == 1: x is correct as-is. Else check vxx == -u.
        # T2_BUF := vxx + u
        addi    a0, sp, T2_BUF
        addi    a1, sp, T1_BUF
        addi    a2, sp, U_BUF
        call    x25519_field_add
        IS_FIELD_ZERO T2_BUF, s4                /* s4 = (vxx == -u)?     */

        # If neither s3 nor s4 is 1, point is invalid.
        or      t0, s3, s4
        bnez    t0, .Ldecompress_valid
        # Invalid point → return 1.
        li      a0, 1
        j       .Ldecompress_done

.Ldecompress_valid:
        # If vxx == -u (s4 == 1, s3 == 0), multiply x by sqrt(-1).
        beqz    s4, .Lskip_sqrt_m1
        addi    a0, sp, X_BUF
        addi    a1, sp, X_BUF
        la      a2, ed25519_sqrt_m1_limbs
        call    x25519_field_mul

.Lskip_sqrt_m1:
        # Adjust sign: if x_LSB != sign_bit, x := -x = (0 - x) mod p.
        # Compute pack(x) and look at byte 0's LSB.
        addi    a0, sp, T3_BUF
        addi    a1, sp, X_BUF
        call    x25519_field_pack
        lbu     t0, T3_BUF(sp)
        andi    t0, t0, 1                       /* x's parity LSB        */
        xor     t0, t0, s2                      /* != sign?              */
        beqz    t0, .Lsign_ok
        # x := 0 - x. Build [0, 0, ...] in T2_BUF.
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, (\i + T2_BUF)(sp)
        .endr
        addi    a0, sp, X_BUF
        addi    a1, sp, T2_BUF
        addi    a2, sp, X_BUF
        call    x25519_field_sub
.Lsign_ok:

        # Write extended-coords output point: X = x, Y = y, Z = 1, T = x*y.
        # X
        addi    t0, sp, X_BUF
        addi    t1, s0, PT_X
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        lw      t2, \i(t0)
        sw      t2, \i(t1)
        .endr
        # Y
        addi    t0, sp, Y_BUF
        addi    t1, s0, PT_Y
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        lw      t2, \i(t0)
        sw      t2, \i(t1)
        .endr
        # Z = 1
        addi    t1, s0, PT_Z
        li      t2, 1
        sw      t2, 0(t1)
        .irp i, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, \i(t1)
        .endr
        # T = x * y
        addi    a0, s0, PT_T
        addi    a1, sp, X_BUF
        addi    a2, sp, Y_BUF
        call    x25519_field_mul

        li      a0, 0                           /* return code 0 = ok    */

.Ldecompress_done:
        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_point_decompress, . - ed25519_point_decompress
