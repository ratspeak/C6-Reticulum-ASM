# ============================================================================
# @function:    ed25519_scalarmult
# @module:      crypto/ed25519
# @inputs:      a0 = out_point ptr (160 bytes; result in extended coords)
#               a1 = scalar_bytes ptr (32 bytes LE)
#               a2 = base_point ptr   (160 bytes; P in extended coords)
# @outputs:     out = scalar · P on edwards25519 (extended coords).
#                     scalar interpreted as a 256-bit LE integer.
# @clobbers:    t0..t6, a3..a7, s0..s5
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       384
# @cycles:      bounded (≈ 256 × (double + add + select) ≈ 9M)
# @ct:          required
# @spec:        Constant-time double-and-add over 256 bits.
#               Each iteration: R = 2·R; tmp = R + P; R = bit ? tmp : R
#               (selected via constant-time mask). No data-dependent
#               branches on the secret scalar — the only conditional
#               branch is the public 256-iteration loop counter.
# @verify:      proofs/crypto/ed25519/Ed25519Encoding.cry, proofs/crypto/ed25519/ed25519_scalarmult.saw
# @tests:       tests/crypto/ed25519/test_ed25519_sign.py
#               (Tier A: SAW + Cryptol prove the boundary-bit-pattern
#               KATs scalarmult(0, B) == O, scalarmult(1, B) == B,
#               scalarmult(2, B) == double(B), and scalarmult(3, B)
#               == double(B) + B — covering the empty, low-bit-only,
#               high-bit-only, and mixed two-bit cases. Tier C bridge:
#               the QEMU sign and verify pytests exercise scalarmult
#               transitively against pyca/cryptography on the full
#               256-bit secret / challenge scalars.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (384 bytes, 16-byte aligned):
 *      0..159   R[160]      (running result)
 *    160..319   tmp[160]    (R + P each iteration)
 *    320..335   pad
 *    336..339   s5
 *    340..343   s4
 *    344..347   s3
 *    348..351   s2
 *    352..355   s1
 *    356..359   s0
 *    360..363   ra
 *    364..383   pad
 *
 * Saved regs:
 *   s0 = out_point ptr
 *   s1 = scalar_bytes ptr
 *   s2 = base_point ptr
 *   s3 = bit counter (255 → 0)
 *   s4 = current bit (0 or 1) — refreshed per iteration
 *   s5 = mask (-bit) — broadcast for the constant-time select
 */

        .include "x25519.S"
        .include "ed25519.S"

        .equ R_OFF,    0
        .equ TMP_OFF, 160
        .equ S5_OFF,  336
        .equ S4_OFF,  340
        .equ S3_OFF,  344
        .equ S2_OFF,  348
        .equ S1_OFF,  352
        .equ S0_OFF,  356
        .equ RA_OFF,  360
        .equ FRAME,   384

        .equ PT_X, 0
        .equ PT_Y, 40
        .equ PT_Z, 80
        .equ PT_T, 120

        .section .text.ed25519_scalarmult, "ax", @progbits
        .global ed25519_scalarmult
        .type   ed25519_scalarmult, @function
ed25519_scalarmult:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        sw      s5, S5_OFF(sp)
        mv      s0, a0
        mv      s1, a1
        mv      s2, a2

        # Initialise R = identity = (X=0, Y=1, Z=1, T=0).
        # 160 bytes: 40 zero (X) + 40 (Y = [1,0,...]) + 40 (Z = [1,0,...]) + 40 zero (T)
        addi    t0, sp, R_OFF
        # X = 0 (40 bytes)
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, \i(t0)
        .endr
        # Y = 1 (canonical: limb_0 = 1, rest 0)
        addi    t0, sp, R_OFF + PT_Y
        li      t1, 1
        sw      t1, 0(t0)
        .irp i, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, \i(t0)
        .endr
        # Z = 1
        addi    t0, sp, R_OFF + PT_Z
        sw      t1, 0(t0)
        .irp i, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, \i(t0)
        .endr
        # T = 0
        addi    t0, sp, R_OFF + PT_T
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, \i(t0)
        .endr

        # Loop: i = 255 down to 0.
        li      s3, 255
.Lsmult_loop:
        # ---- 1. R = 2 * R (double) ----
        addi    a0, sp, R_OFF
        addi    a1, sp, R_OFF
        call    ed25519_point_double

        # ---- 2. tmp = R + P (always; the result is conditionally adopted) ----
        addi    a0, sp, TMP_OFF
        addi    a1, sp, R_OFF
        mv      a2, s2
        call    ed25519_point_add

        # ---- 3. Extract bit s3 of scalar (LE) into s4 ----
        srli    t0, s3, 3                        /* byte index            */
        add     t0, s1, t0
        lbu     t0, 0(t0)
        andi    t1, s3, 7
        srl     t0, t0, t1
        andi    s4, t0, 1
        # mask = -bit (0 or 0xFFFFFFFF)
        sub     s5, zero, s4

        # ---- 4. R := bit ? tmp : R    (constant-time per word) ----
        # 160 bytes = 40 words of 4 bytes each. Loop with a counter.
        addi    a3, sp, R_OFF                    /* &R                    */
        addi    a4, sp, TMP_OFF                  /* &tmp                  */
        li      a5, 40                           /* word count            */
.Lselect_loop:
        lw      t0, 0(a3)                        /* R[i]                  */
        lw      t1, 0(a4)                        /* tmp[i]                */
        xor     t2, t0, t1                       /* xor                   */
        and     t2, t2, s5                       /* mask                  */
        xor     t0, t0, t2                       /* select                */
        sw      t0, 0(a3)
        addi    a3, a3, 4
        addi    a4, a4, 4
        addi    a5, a5, -1
        bnez    a5, .Lselect_loop

        # ---- 5. bit_counter -- ; loop ----
        addi    s3, s3, -1
        bgez    s3, .Lsmult_loop

        # ---- 6. Copy R → out_point (40 bytes × 4 = 160 bytes) ----
        addi    a3, sp, R_OFF
        mv      a4, s0
        li      a5, 40
.Lcopy_out:
        lw      t0, 0(a3)
        sw      t0, 0(a4)
        addi    a3, a3, 4
        addi    a4, a4, 4
        addi    a5, a5, -1
        bnez    a5, .Lcopy_out

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        lw      s5, S5_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_scalarmult, . - ed25519_scalarmult
