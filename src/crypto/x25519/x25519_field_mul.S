# ============================================================================
# @function:    x25519_field_mul
# @module:      crypto/x25519
# @inputs:      a0 = out limbs ptr (40 bytes)
#               a1 = a   limbs ptr (40 bytes)
#               a2 = b   limbs ptr (40 bytes; may alias a1 or out)
# @outputs:     out = (a * b) mod p_25519, in radix-2^25.5 form, with limbs
#                     reduced into nominal width.
# @clobbers:    t0..t6, a3..a7
# @preserves:   sp, gp, ra, a0, a1, a2, all callee-saved
# @stack:       160
# @cycles:      bounded (~1500: 100 muls + degree fold + carry propagation)
# @ct:          required
# @spec:        donna 32-bit `fmul` = `fproduct` (10×10 polynomial multiply
#               with the (i,j) both-odd ×2 doubling) followed by
#               `freduce_degree` (cells 10..18 fold back into 0..8 with
#               weight 19, since 2^255 ≡ 19 mod p_25519) followed by
#               `freduce_coefficients` (two carry passes, with the
#               limb 9 → limb 0 ×19 fold between/after each).
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_mul.saw, proofs/crypto/x25519/x25519_field_mul.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_mul.py
#               (Tier C bridge: the angr pcode RV32IMC engine miscompiles
#               64-bit mul/mulh/add-with-carry chains (same blocker as
#               x25519_field_mul121665 — see ADR-0009 §"Tier C path
#               forward"). Binary equivalence is provided by the QEMU
#               pytest KAT here, which drives the asm under
#               qemu-system-riscv32 on five edge cases plus six random
#               inputs and compares each output against the Python
#               oracle, which is itself verified against the Integer
#               algebraic spec on 50 random inputs in the oracle
#               self-test.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* fmul(out, a, b):
 *
 *   # Stage 1: fproduct — 19 64-bit accumulator cells.
 *   for k in 0..18: cell[k] = 0
 *   for i in 0..9:
 *     for j in 0..9:
 *       prod = a[i] * b[j]                # 64-bit signed product
 *       if (i & 1) and (j & 1): prod *= 2 # radix-2^25.5 alignment fixup
 *       cell[i+j] += prod                 # 64-bit accumulate
 *
 *   # Stage 2: freduce_degree — fold cells 10..18 into 0..8 with weight 19.
 *   for k in 10..18: cell[k - 10] += 19 * cell[k]
 *
 *   # Stage 3: freduce_coefficients — two carry passes with the limb-9
 *   # fold (×19 into limb 0) between passes and at the end.
 *   for round in 0..1:
 *     for i in 0..8:
 *       carry = cell[i] >> width_i        # 64-bit arithmetic shift
 *       cell[i] -= carry << width_i
 *       cell[i+1] += carry
 *     carry = cell[9] >> 25
 *     cell[9] -= carry << 25
 *     cell[0] += 19 * carry
 *
 *   for i in 0..9: out[i] = cell[i] (low 32 bits)
 *
 * Stack frame (sp+0..sp+159, 16-byte aligned):
 *   sp +   0 .. sp + 151:  19 64-bit cells (cell[k] at sp + k*8)
 *   sp + 152 .. sp + 159:  pad
 *
 * Per-product accumulator math (PRODUCT_AT i, j):
 *   a3 holds a[i] (loaded once per outer-loop iteration).
 *   a4 = b[j] (loaded each inner step).
 *   a5:a6 = product (low:high). Optionally doubled.
 *   t0..t3 scratch for cell load, add-with-carry, store.
 *
 * 19 * (signed 64-bit) computation (FOLD_DEGREE k, LAST_CARRY):
 *   Treat cell as (hi:lo) where lo is interpreted unsigned.
 *   19 * cell = 19*lo + (19*hi) << 32  (mod 2^64)
 *   low 32  = mul(lo, 19)
 *   high 32 = mulhu(lo, 19) + mul(hi, 19)   # high of 19*lo + low of 19*hi
 */

        .include "x25519.S"

        # --- macros ---------------------------------------------------

        # PRODUCT_AT i, j: accumulate a[i]*b[j] (×2 if both i,j odd) into
        # the 64-bit cell at sp + (i+j)*8. Caller must have a[i] in a3.
        .macro PRODUCT_AT i, j
        lw      a4, (\j*4)(a2)               /* b[j]                    */
        mul     a5, a3, a4                   /* prod_lo = a[i]*b[j]     */
        mulh    a6, a3, a4                   /* prod_hi (signed)        */
        .if ((\i & 1) * (\j & 1))
        srli    t0, a5, 31                   /* doubling: shift left 1  */
        slli    a6, a6, 1
        or      a6, a6, t0
        slli    a5, a5, 1
        .endif
        lw      t0, ((\i+\j)*8)(sp)          /* cell_lo                 */
        lw      t1, ((\i+\j)*8 + 4)(sp)      /* cell_hi                 */
        add     t2, t0, a5                   /* new_lo                  */
        sltu    t3, t2, a5                   /* unsigned carry          */
        add     t1, t1, a6
        add     t1, t1, t3
        sw      t2, ((\i+\j)*8)(sp)
        sw      t1, ((\i+\j)*8 + 4)(sp)
        .endm

        # FOLD_DEGREE k: cell[k-10] += 19 * cell[k]   (k in 10..18).
        # Computes 19 * (signed 64-bit) and 64-bit-adds to the lower cell.
        .macro FOLD_DEGREE k
        lw      t0, (\k*8)(sp)               /* hi_cell_lo              */
        lw      t1, (\k*8 + 4)(sp)           /* hi_cell_hi              */
        li      t2, 19
        mul     t3, t0, t2                   /* low 32 of 19*lo         */
        mulhu   t4, t0, t2                   /* high 32 of 19*lo (uns.) */
        mul     t5, t1, t2                   /* low 32 of 19*hi         */
        add     t4, t4, t5                   /* high 32 of 19 * cell    */
        lw      t0, ((\k-10)*8)(sp)          /* dst_lo                  */
        lw      t1, ((\k-10)*8 + 4)(sp)      /* dst_hi                  */
        add     t5, t0, t3
        sltu    t6, t5, t3
        add     t1, t1, t4
        add     t1, t1, t6
        sw      t5, ((\k-10)*8)(sp)
        sw      t1, ((\k-10)*8 + 4)(sp)
        .endm

        # CARRY_CELL i, width: forward-carry the bits above width_i out
        # of cell[i] into cell[i+1]. cell[i] left in [0, 2^width_i).
        # Uses 64-bit arithmetic right shift.
        .macro CARRY_CELL i, width
        lw      t0, (\i*8)(sp)
        lw      t1, (\i*8 + 4)(sp)
        slli    t2, t1, (32 - \width)        /* low part of carry       */
        srli    t3, t0, \width
        or      t2, t2, t3                   /* carry_lo                */
        srai    t3, t1, \width               /* carry_hi (signed)       */
        li      t4, ((1 << \width) - 1)
        and     t0, t0, t4
        sw      t0, (\i*8)(sp)
        sw      zero, (\i*8 + 4)(sp)         /* high cleared after mask */
        lw      t0, ((\i+1)*8)(sp)
        lw      t1, ((\i+1)*8 + 4)(sp)
        add     t4, t0, t2
        sltu    t5, t4, t2
        add     t1, t1, t3
        add     t1, t1, t5
        sw      t4, ((\i+1)*8)(sp)
        sw      t1, ((\i+1)*8 + 4)(sp)
        .endm

        # LAST_CARRY: cell[9] (width 25) → cell[0] (×19, 64-bit add).
        .macro LAST_CARRY
        lw      t0, (9*8)(sp)
        lw      t1, (9*8 + 4)(sp)
        slli    t2, t1, (32 - 25)
        srli    t3, t0, 25
        or      t2, t2, t3                   /* carry_lo                */
        srai    t3, t1, 25                   /* carry_hi (signed)       */
        li      t4, ((1 << 25) - 1)
        and     t0, t0, t4
        sw      t0, (9*8)(sp)
        sw      zero, (9*8 + 4)(sp)
        # 19 * (t3:t2) → (t6:t5) via mul/mulhu/mul + add (same as FOLD_DEGREE).
        li      t4, 19
        mul     t5, t2, t4
        mulhu   t6, t2, t4
        mul     a3, t3, t4
        add     t6, t6, a3
        lw      t0, 0(sp)
        lw      t1, 4(sp)
        add     a3, t0, t5
        sltu    a4, a3, t5
        add     t1, t1, t6
        add     t1, t1, a4
        sw      a3, 0(sp)
        sw      t1, 4(sp)
        .endm

        # CARRY_PROPAGATE_PASS: one full pass through cells 0..9 with the
        # limb-9 → limb-0 fold.
        .macro CARRY_PROPAGATE_PASS
        CARRY_CELL 0, 26
        CARRY_CELL 1, 25
        CARRY_CELL 2, 26
        CARRY_CELL 3, 25
        CARRY_CELL 4, 26
        CARRY_CELL 5, 25
        CARRY_CELL 6, 26
        CARRY_CELL 7, 25
        CARRY_CELL 8, 26
        LAST_CARRY
        .endm

        # --- entry ----------------------------------------------------

        .section .text.x25519_field_mul, "ax", @progbits
        .global x25519_field_mul
        .type   x25519_field_mul, @function
x25519_field_mul:
        addi    sp, sp, -160

        # Zero-init cells 0..18 (152 bytes).
        .irp k, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
        sw      zero, (\k*8)(sp)
        sw      zero, (\k*8 + 4)(sp)
        .endr

        # fproduct: 10×10 = 100 word multiplications, accumulated into cells.
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      a3, (\i*4)(a1)               /* a[i] held in a3         */
        .irp j, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        PRODUCT_AT \i, \j
        .endr
        .endr

        # freduce_degree: cells 10..18 fold back into 0..8 with weight 19.
        .irp k, 10, 11, 12, 13, 14, 15, 16, 17, 18
        FOLD_DEGREE \k
        .endr

        # freduce_coefficients: two carry passes.
        CARRY_PROPAGATE_PASS
        CARRY_PROPAGATE_PASS

        # Copy 10 limbs (low 32 of each cell) to output.
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*8)(sp)
        sw      t0, (\i*4)(a0)
        .endr

        addi    sp, sp, 160
        ret

        .size   x25519_field_mul, . - x25519_field_mul
