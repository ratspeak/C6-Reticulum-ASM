# ============================================================================
# @function:    ed25519_sc_muladd
# @module:      crypto/ed25519
# @inputs:      a0 = out ptr (32 bytes; (a*b + c) mod L, LE)
#               a1 = a   ptr (32 bytes; LE scalar)
#               a2 = b   ptr (32 bytes; LE scalar)
#               a3 = c   ptr (32 bytes; LE scalar)
# @outputs:     out = (a*b + c) mod L, encoded as 32 LE bytes
# @clobbers:    t0..t6, a4..a7, s0..s5
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       96
# @cycles:      bounded (≈ 8×8 schoolbook mul (~700) + c add (~50) +
#                        sc_reduce (~36K) ≈ 37K)
# @ct:          required
# @spec:        sc_muladd(a, b, c) = (a · b + c) mod L. Schoolbook 8×8
#               word multiplication into a 64-byte product, then
#               add c (with carry propagation through the high half),
#               then reduce mod L via ed25519_sc_reduce.
# @verify:      proofs/crypto/ed25519/Ed25519Scalar.cry, proofs/crypto/ed25519/ed25519_sc_muladd.saw
# @tests:       tests/crypto/ed25519/test_ed25519_sc_muladd.py
#               (Tier A: SAW + Cryptol prove (a*b + c) mod L matches
#               the integer-arithmetic spec on seven concrete vectors:
#               (0,0,0), (1,1,0), (L,1,0), (1,L,0), (L-1,L-1,0),
#               (0,0,L-1), and one random 256-bit triple. Tier C
#               bridge: the QEMU pytest covers the random-input space
#               against the same Python oracle.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (96 bytes, 16-byte aligned):
 *      0..63    prod[16]   (64-byte schoolbook product accumulator,
 *                            also receives c added into the low half)
 *     64..67    ra
 *     68..91    s0..s5     (24 bytes)
 *     92..95    pad
 *
 * Saved regs:
 *   s0 = out ptr
 *   s1 = a ptr
 *   s2 = b ptr
 *   s3 = c ptr
 *   s4..s5 = scratch in inner loops
 */

        .include "ed25519.S"

        .equ PROD_OFF, 0
        .equ RA_OFF,  64
        .equ S0_OFF,  68
        .equ S1_OFF,  72
        .equ S2_OFF,  76
        .equ S3_OFF,  80
        .equ S4_OFF,  84
        .equ S5_OFF,  88
        .equ FRAME,   96

        .section .text.ed25519_sc_muladd, "ax", @progbits
        .global ed25519_sc_muladd
        .type   ed25519_sc_muladd, @function
ed25519_sc_muladd:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        sw      s5, S5_OFF(sp)

        mv      s0, a0                          /* out ptr               */
        mv      s1, a1                          /* a ptr                 */
        mv      s2, a2                          /* b ptr                 */
        mv      s3, a3                          /* c ptr                 */

        # Zero prod[0..15]
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60
        sw      zero, (\i + PROD_OFF)(sp)
        .endr

        # ---- 8x8 schoolbook multiplication: prod[16] = a[8] * b[8] ----
        # Outer loop over rows i (0..7). Inner: row of partial products.
        # Inner kernel per (i, j): prod[i+j] += a[i]*b[j] + carry; carry
        # is the high 32 bits of the running 64-bit accumulator.
        li      s4, 0                            /* row counter i         */
.Lrow:
        slli    s5, s4, 2                        /* &a[i] = s1 + i*4      */
        add     s5, s1, s5
        lw      a4, 0(s5)                        /* a[i] in a4            */
        li      a5, 0                            /* carry in a5           */
        li      a6, 0                            /* col counter j         */
.Lcol:
        slli    a7, a6, 2                        /* &b[j]                 */
        add     a7, s2, a7
        lw      a7, 0(a7)                        /* b[j] in a7            */

        # 32x32 = 64-bit product (a4 * a7) → (t1:t0)
        mul     t0, a4, a7
        mulhu   t1, a4, a7

        # &prod[i+j] = sp + (i+j)*4
        add     t2, s4, a6
        slli    t2, t2, 2
        add     t2, sp, t2                       /* &prod[i+j]            */
        lw      t3, 0(t2)                        /* current prod[i+j]     */

        # Accumulate: prod[i+j] += a[i]*b[j] + carry
        add     t4, t3, t0                       /* + low                 */
        sltu    t5, t4, t0
        add     t4, t4, a5                       /* + incoming carry      */
        sltu    t6, t4, a5
        sw      t4, 0(t2)
        add     t1, t1, t5
        add     t1, t1, t6                       /* new carry = hi + carry_outs */
        mv      a5, t1

        addi    a6, a6, 1
        li      t0, 8
        bne     a6, t0, .Lcol

        # End of row: store final carry to prod[i+8].
        addi    t2, s4, 8
        slli    t2, t2, 2
        add     t2, sp, t2
        sw      a5, 0(t2)

        addi    s4, s4, 1
        li      t0, 8
        bne     s4, t0, .Lrow

        # ---- Add c (32 bytes) into prod[0..7] with carry to prod[8..15] ----
        li      a4, 0                            /* carry                 */
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, (\i + PROD_OFF)(sp)
        lw      t1, \i(s3)
        add     t2, t0, t1
        sltu    t3, t2, t1
        add     t2, t2, a4
        sltu    t4, t2, a4
        sw      t2, (\i + PROD_OFF)(sp)
        add     a4, t3, t4                       /* carry = sum of carries */
        .endr

        # Propagate any leftover carry into prod[8..15] (low offset 32).
        beqz    a4, .Lpost_add
        .irp i, 32, 36, 40, 44, 48, 52, 56, 60
        lw      t0, (\i + PROD_OFF)(sp)
        add     t1, t0, a4
        sltu    a4, t1, a4
        sw      t1, (\i + PROD_OFF)(sp)
        beqz    a4, .Lpost_add
        .endr
.Lpost_add:

        # ---- Call ed25519_sc_reduce(out, prod_buffer) ----
        mv      a0, s0
        addi    a1, sp, PROD_OFF
        call    ed25519_sc_reduce

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        lw      s5, S5_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_sc_muladd, . - ed25519_sc_muladd
