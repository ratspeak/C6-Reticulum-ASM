# ============================================================================
# @function:    x25519_field_pack
# @module:      crypto/x25519
# @inputs:      a0 = out bytes ptr  (32 bytes; little-endian wire form)
#               a1 = in limbs ptr   (40 bytes; 10 × int32, possibly non-canonical)
# @outputs:     out = canonical 32-byte little-endian encoding of
#                     (decode_limbs in) mod p_25519, with 0 ≤ value < p.
# @clobbers:    t0..t6, a2..a7
# @preserves:   sp, gp, ra, a0, a1, all callee-saved
# @stack:       80
# @cycles:      bounded (~270: load + 3×carry-rounds + sub + select + pack)
# @ct:          required
# @spec:        donna 32-bit `fcontract` — three rounds of signed carry
#               propagation (with the 2^255 ≡ 19 fold of limb 9's overflow
#               into limb 0), followed by a constant-time conditional
#               subtract of p, followed by bit-stream packing into 32 bytes.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_field_pack.saw, proofs/crypto/x25519/x25519_field_pack.py, proofs/crypto/x25519/x25519_field_pack.bsc
# @tests:       tests/crypto/x25519/test_x25519_field_pack.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* fcontract(out_bytes, in_limbs):
 *
 *   limbs[10] := copy of in_limbs   (signed; possibly non-nominal width)
 *
 *   for round in 0..2:
 *     for i in 0..8:
 *       carry  = limbs[i] >> width_i      (arithmetic; width 26 or 25)
 *       limbs[i]   -= carry << width_i    (= limbs[i] mod 2^width_i, signed-aware)
 *       limbs[i+1] += carry
 *     carry = limbs[9] >> 25
 *     limbs[9] -= carry << 25
 *     limbs[0] += 19 * carry              (fold weight 2^255 → 1)
 *
 *   # Now 0 ≤ limbs[i] < 2^width_i for all i, and value V is in [0, 2^255).
 *
 *   r[10], borrow := limbs - p          (limb-wise; borrow propagated)
 *   if borrow == -1: V < p, output limbs.
 *   else:            output r           (= V - p, in [0, 19)).
 *   # constant-time select via mask = sign-extension of final borrow
 *
 *   pack canonical limbs into 32 bytes by bit-stream layout:
 *     limb 0 → bits   0..25    (low 26 bits of bytes 0..3)
 *     limb 1 → bits  26..50    (start byte 3 bit 2; 25 bits)
 *     limb 2 → bits  51..76
 *     ...
 *     limb 9 → bits 230..254   (bit 255 = 0)
 *
 * Stack frame:  sp+0..sp+36  working limbs (modified by carry rounds)
 *               sp+40..sp+76 r-buffer (limbs - p with borrow propagation)
 *               total 80 bytes (16-byte aligned).
 *
 * Constants:
 *   a2 = MASK_26 = 0x03FFFFFF  (and = p[2,4,6,8])
 *   a3 = MASK_25 = 0x01FFFFFF  (and = p[1,3,5,7,9])
 *   t5 = P_LIMB_0 = 0x03FFFFED = 2^26 - 19
 */

        .include "x25519.S"

        .equ MASK_25,           0x01FFFFFF
        .equ MASK_26,           0x03FFFFFF
        # p[0] = 2^26 - 19 = (MASK_26 + 1) - 19 = MASK_26 - 18 = 0x03FFFFED.
        # Derived from a2 (which holds MASK_26) with a single addi.
        .equ P_LIMB_0_OFFSET,   -18

        # CARRY_FWD: forward carry from limb i (width \width) into limb i+1.
        .macro CARRY_FWD i, width
        lw      t0, (\i*4)(sp)
        srai    t1, t0, \width                /* carry (signed)          */
        slli    t2, t1, \width
        sub     t0, t0, t2                    /* limb[i] -= carry << w   */
        sw      t0, (\i*4)(sp)
        lw      t0, ((\i+1)*4)(sp)
        add     t0, t0, t1
        sw      t0, ((\i+1)*4)(sp)
        .endm

        # CARRY_LAST: limb 9's overflow folds back into limb 0 with weight 19.
        .macro CARRY_LAST
        lw      t0, 36(sp)
        srai    t1, t0, 25
        slli    t2, t1, 25
        sub     t0, t0, t2
        sw      t0, 36(sp)
        # 19 * t1 = (16 * t1) + (2 * t1) + t1
        slli    t2, t1, 4
        slli    t3, t1, 1
        add     t2, t2, t3
        add     t2, t2, t1
        lw      t0, 0(sp)
        add     t0, t0, t2
        sw      t0, 0(sp)
        .endm

        # SUB_LIMB: r[i] := (limbs[i] - p[i] + borrow) & mask_i; borrow updated.
        # \p_reg holds p[i]; for i=0 it's t5, for i in [1..9] it's a2 or a3 (mask).
        # \mask_reg is a2 (MASK_26) or a3 (MASK_25).
        # \width is 26 or 25.
        # t6 carries the borrow (0 or -1 sign-extended) across calls.
        .macro SUB_LIMB i, width, mask_reg, p_reg
        lw      t0, (\i*4)(sp)
        sub     t0, t0, \p_reg
        add     t0, t0, t6                    /* apply incoming borrow   */
        srai    t6, t0, \width                /* outgoing borrow         */
        and     t0, t0, \mask_reg
        sw      t0, (\i*4 + 40)(sp)
        .endm

        .section .text.x25519_field_pack, "ax", @progbits
        .global x25519_field_pack
        .type   x25519_field_pack, @function
x25519_field_pack:
        addi    sp, sp, -80

        # Step 1: copy input limbs onto stack working area.
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4)(a1)
        sw      t0, (\i*4)(sp)
        .endr

        # Step 2: three rounds of signed carry propagation.
        .rept 3
        CARRY_FWD 0, 26
        CARRY_FWD 1, 25
        CARRY_FWD 2, 26
        CARRY_FWD 3, 25
        CARRY_FWD 4, 26
        CARRY_FWD 5, 25
        CARRY_FWD 6, 26
        CARRY_FWD 7, 25
        CARRY_FWD 8, 26
        CARRY_LAST
        .endr

        # Step 3: r := limbs - p, with borrow propagation, into sp+40..sp+76.
        li      a2, MASK_26
        li      a3, MASK_25
        addi    t5, a2, P_LIMB_0_OFFSET       /* t5 = 0x03FFFFED = p[0]  */
        li      t6, 0                         /* initial borrow = 0      */

        SUB_LIMB 0, 26, a2, t5
        SUB_LIMB 1, 25, a3, a3
        SUB_LIMB 2, 26, a2, a2
        SUB_LIMB 3, 25, a3, a3
        SUB_LIMB 4, 26, a2, a2
        SUB_LIMB 5, 25, a3, a3
        SUB_LIMB 6, 26, a2, a2
        SUB_LIMB 7, 25, a3, a3
        SUB_LIMB 8, 26, a2, a2
        SUB_LIMB 9, 25, a3, a3

        # t6 = 0 (no final borrow → limbs ≥ p, use r) or -1 (limbs < p, use limbs).
        # Constant-time select into the working limbs slot (sp+0..36):
        #   final[i] = r[i] ^ ((r[i] ^ limbs[i]) & mask),   mask = t6.
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4 + 40)(sp)
        lw      t1, (\i*4)(sp)
        xor     t2, t0, t1
        and     t2, t2, t6
        xor     t0, t0, t2
        sw      t0, (\i*4)(sp)
        .endr

        # Step 4: pack canonical limbs into 32 little-endian wire bytes.
        # Load all 10 limbs into registers (a2..a7, t0..t3) so the byte
        # extraction is one srli (or srli+slli+or for boundary bytes)
        # plus one sb per output byte. sb stores the low 8 bits, so the
        # high bits of OR-merged operands are harmless.
        lw      a2,  0(sp)              /* limb 0 */
        lw      a3,  4(sp)              /* limb 1 */
        lw      a4,  8(sp)              /* limb 2 */
        lw      a5, 12(sp)              /* limb 3 */
        lw      a6, 16(sp)              /* limb 4 */
        lw      a7, 20(sp)              /* limb 5 */
        lw      t0, 24(sp)              /* limb 6 */
        lw      t1, 28(sp)              /* limb 7 */
        lw      t2, 32(sp)              /* limb 8 */
        lw      t3, 36(sp)              /* limb 9 */

        # bytes 0..2: limb 0 (bits 0..23)
        sb      a2,  0(a0)
        srli    t4, a2, 8
        sb      t4,  1(a0)
        srli    t4, a2, 16
        sb      t4,  2(a0)
        # byte 3: limb_0[24..25] || limb_1[0..5]
        srli    t4, a2, 24
        slli    t6, a3, 2
        or      t4, t4, t6
        sb      t4,  3(a0)
        # bytes 4..5: limb 1 (bits 6..21)
        srli    t4, a3, 6
        sb      t4,  4(a0)
        srli    t4, a3, 14
        sb      t4,  5(a0)
        # byte 6: limb_1[22..24] || limb_2[0..4]
        srli    t4, a3, 22
        slli    t6, a4, 3
        or      t4, t4, t6
        sb      t4,  6(a0)
        # bytes 7..8: limb 2 (bits 5..20)
        srli    t4, a4, 5
        sb      t4,  7(a0)
        srli    t4, a4, 13
        sb      t4,  8(a0)
        # byte 9: limb_2[21..25] || limb_3[0..2]
        srli    t4, a4, 21
        slli    t6, a5, 5
        or      t4, t4, t6
        sb      t4,  9(a0)
        # bytes 10..11: limb 3 (bits 3..18)
        srli    t4, a5, 3
        sb      t4, 10(a0)
        srli    t4, a5, 11
        sb      t4, 11(a0)
        # byte 12: limb_3[19..24] || limb_4[0..1]
        srli    t4, a5, 19
        slli    t6, a6, 6
        or      t4, t4, t6
        sb      t4, 12(a0)
        # bytes 13..15: limb 4 (bits 2..25)
        srli    t4, a6, 2
        sb      t4, 13(a0)
        srli    t4, a6, 10
        sb      t4, 14(a0)
        srli    t4, a6, 18
        sb      t4, 15(a0)
        # bytes 16..18: limb 5 (bits 0..23)
        sb      a7, 16(a0)
        srli    t4, a7, 8
        sb      t4, 17(a0)
        srli    t4, a7, 16
        sb      t4, 18(a0)
        # byte 19: limb_5[24] || limb_6[0..6]
        srli    t4, a7, 24
        slli    t6, t0, 1
        or      t4, t4, t6
        sb      t4, 19(a0)
        # bytes 20..21: limb 6 (bits 7..22)
        srli    t4, t0, 7
        sb      t4, 20(a0)
        srli    t4, t0, 15
        sb      t4, 21(a0)
        # byte 22: limb_6[23..25] || limb_7[0..4]
        srli    t4, t0, 23
        slli    t6, t1, 3
        or      t4, t4, t6
        sb      t4, 22(a0)
        # bytes 23..24: limb 7 (bits 5..20)
        srli    t4, t1, 5
        sb      t4, 23(a0)
        srli    t4, t1, 13
        sb      t4, 24(a0)
        # byte 25: limb_7[21..24] || limb_8[0..3]
        srli    t4, t1, 21
        slli    t6, t2, 4
        or      t4, t4, t6
        sb      t4, 25(a0)
        # bytes 26..27: limb 8 (bits 4..19)
        srli    t4, t2, 4
        sb      t4, 26(a0)
        srli    t4, t2, 12
        sb      t4, 27(a0)
        # byte 28: limb_8[20..25] || limb_9[0..1]
        srli    t4, t2, 20
        slli    t6, t3, 6
        or      t4, t4, t6
        sb      t4, 28(a0)
        # bytes 29..31: limb 9 (bits 2..24); bit 255 = 0.
        srli    t4, t3, 2
        sb      t4, 29(a0)
        srli    t4, t3, 10
        sb      t4, 30(a0)
        srli    t4, t3, 18
        sb      t4, 31(a0)

        addi    sp, sp, 80
        ret

        .size   x25519_field_pack, . - x25519_field_pack
