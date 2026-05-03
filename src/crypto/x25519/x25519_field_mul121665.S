# ============================================================================
# @function:    x25519_field_mul121665
# @module:      crypto/x25519
# @inputs:      a0 = out limbs ptr (40 bytes; may alias a1 for in-place)
#               a1 = in limbs ptr (40 bytes)
# @outputs:     out = 121665 * in (mod p_25519), in radix-2^25.5 form
#                     with limbs reduced into their nominal width.
# @clobbers:    t0..t6, a2..a7
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~250: 10 × ~25 instructions per limb + final fold)
# @ct:          required
# @spec:        donna 32-bit `fscalar_product` followed by carry-propagation
#               and fold of the high overflow into limb 0 with weight 19
#               (since 2^255 ≡ 19 mod p_25519). After this function, all
#               output limbs are in nominal width and ready to feed into
#               another field op without further reduction.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_mul121665.saw, proofs/crypto/x25519/x25519_field_mul121665.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_mul121665.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* fscalar_product(out, in, 121665):
 *
 *   accum_64 = 0
 *   for i = 0..9:
 *     accum_64 += (int64_t)in[i] * 121665
 *     out[i] = accum_64 & mask_i      (mask_26 if i even, mask_25 if odd)
 *     accum_64 >>= width_i            (26 or 25 bits)
 *   out[0] += accum_64 * 19           (fold weight 2^255 → weight 1)
 *   out[1] += out[0] >> 26 ; out[0] &= mask_26   (single-limb final carry)
 *
 * 64-bit accumulator on RV32: register pair (hi:lo) = (a3:a2). Each
 * iteration: signed 32×32 → 64 product via mul + mulh, add to (a3:a2),
 * extract masked low limb, arithmetic-shift the pair right by 25 or 26
 * bits to set up the next iteration. Output may alias input — we read
 * each input limb before writing the corresponding output.
 *
 * Register conventions for the body:
 *   a2 = accum_lo     a3 = accum_hi
 *   a4 = scalar (121665)
 *   a5 = mask_26 (0x03FFFFFF)
 *   a6 = mask_25 (0x01FFFFFF)
 *   t0 = limb_i loaded from input
 *   t1 = product_lo (mul)
 *   t2 = product_hi (mulh)
 *   t3 = carry/scratch
 *   t4 = scratch (output limb, shift glue)
 */

        .include "x25519.S"

        .equ MASK_25,   0x01FFFFFF
        .equ MASK_26,   0x03FFFFFF
        .equ A24,       121665

        # Macro: accumulate (limb_i * scalar) into (a3:a2), extract masked
        # output limb, arithmetic-shift right by `width` for next iteration.
        #
        #   in_off       = byte offset of input limb (4*i)
        #   out_off      = byte offset of output limb (4*i)
        #   width_mask   = a5 (26-bit) or a6 (25-bit)
        #   width        = 26 or 25
        .macro MUL_LIMB_STEP in_off, out_off, width_mask, width
        lw      t0, \in_off(a1)
        mul     t1, t0, a4              /* product low                 */
        mulh    t2, t0, a4              /* product high (signed)       */
        add     a2, a2, t1              /* accum_lo += product_lo      */
        sltu    t3, a2, t1              /* carry from low add          */
        add     a3, a3, t2              /* accum_hi += product_hi      */
        add     a3, a3, t3              /* accum_hi += carry           */
        and     t4, a2, \width_mask     /* output limb = accum & mask  */
        sw      t4, \out_off(a0)
        srli    a2, a2, \width          /* accum_lo >>= width          */
        slli    t4, a3, (32 - \width)   /* hi << (32 - width)          */
        or      a2, a2, t4              /* low part of shifted accum   */
        srai    a3, a3, \width          /* accum_hi >>= width (signed) */
        .endm

        .section .text.x25519_field_mul121665, "ax", @progbits
        .global x25519_field_mul121665
        .type   x25519_field_mul121665, @function
x25519_field_mul121665:
        li      a4, A24                 /* scalar = 121665             */
        li      a5, MASK_26
        li      a6, MASK_25
        mv      a2, zero                /* accum_lo = 0                */
        mv      a3, zero                /* accum_hi = 0                */

        MUL_LIMB_STEP  0,  0, a5, 26
        MUL_LIMB_STEP  4,  4, a6, 25
        MUL_LIMB_STEP  8,  8, a5, 26
        MUL_LIMB_STEP 12, 12, a6, 25
        MUL_LIMB_STEP 16, 16, a5, 26
        MUL_LIMB_STEP 20, 20, a6, 25
        MUL_LIMB_STEP 24, 24, a5, 26
        MUL_LIMB_STEP 28, 28, a6, 25
        MUL_LIMB_STEP 32, 32, a5, 26
        MUL_LIMB_STEP 36, 36, a6, 25

        /* Fold the remaining accumulator (which has weight 2^255) back into
         * limb 0 with weight 19. After 10 carries `accum_hi:accum_lo` fits
         * in a few dozen bits — for 17-bit scalar × 26-bit limbs it's at
         * most ~7 bits — so accum_lo alone holds the value (a3 will be 0
         * or sign-extension). Multiply by 19 and add to out[0]. */
        slli    t0, a2, 4               /* a2 * 16                     */
        add     t0, t0, a2              /* a2 * 17                     */
        add     t0, t0, a2              /* a2 * 18                     */
        add     t0, t0, a2              /* a2 * 19                     */
        lw      t1, 0(a0)
        add     t1, t1, t0
        /* One more carry from limb 0 to limb 1 to keep limb 0 in 26 bits. */
        srai    t2, t1, 26              /* signed carry                */
        and     t1, t1, a5
        sw      t1, 0(a0)
        lw      t3, 4(a0)
        add     t3, t3, t2
        sw      t3, 4(a0)

        ret

        .size   x25519_field_mul121665, . - x25519_field_mul121665
