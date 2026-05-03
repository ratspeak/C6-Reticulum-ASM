# ============================================================================
# @function:    x25519_montgomery_ladder
# @module:      crypto/x25519
# @inputs:      a0 = out_limbs ptr (40 bytes; result x_2/z_2 in field form)
#               a1 = k_bytes ptr   (32 bytes; clamped scalar wire form)
#               a2 = u_limbs ptr   (40 bytes; u-coordinate already unpacked
#                                   with RFC 7748 §5 high-bit mask applied)
# @outputs:     out_limbs = (k * P_u).x in field form, where P_u is the
#                           Montgomery curve point with x-coordinate = u.
# @clobbers:    t0..t6, a3..a7, s0..s4
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       640
# @cycles:      bounded (255 iters × ~10 field ops per iter, plus one
#               field_inv at the end ≈ 4 × 10^6)
# @ct:          required
# @spec:        RFC 7748 §5: Montgomery ladder. For t = 254 down to 0:
#               k_t = (k >> t) & 1; cswap by (swap XOR k_t); apply
#               Montgomery double-and-add formulas; swap = k_t. After
#               the loop, conditional-swap by the residual swap, then
#               compute x_2 / z_2 = x_2 * z_2^(p-2). The loop is data-
#               independent — counter is t, not k — and cswap is
#               constant-time, so the function is constant-time wrt k.
# @verify:      proofs/crypto/x25519/X25519.cry, proofs/crypto/x25519/x25519_montgomery_ladder.saw
# @tests:       tests/crypto/x25519/test_x25519_montgomery_ladder.py
#               (Tier C bridge: QEMU pytest drives the ladder on RFC
#               7748 §5.2 and §6.1 vectors and compares the resulting
#               x_2/z_2 limbs against the algebraic-spec-validated
#               Python oracle, i.e. transitively against RFC 7748.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* fmonty body (per iteration), reading from current (x_2, z_2, x_3, z_3),
 * writing back into the same buffers. Components A..CB live in fresh
 * stack slots so the originals aren't clobbered before they're read.
 *
 *   A  = x_2 + z_2          C  = x_3 + z_3
 *   B  = x_2 - z_2          D  = x_3 - z_3
 *   AA = A^2                BB = B^2
 *   E  = AA - BB
 *   DA = D * A              CB = C * B
 *   x_3 = (DA + CB)^2       z_3 = x_1 * (DA - CB)^2
 *   x_2 = AA * BB           z_2 = E * (AA + a24 * E)
 *
 * Stack layout (640 bytes, 16-byte aligned):
 *   sp+  0..39   x_1   (constant across iterations)
 *   sp+ 40..79   x_2
 *   sp+ 80..119  z_2
 *   sp+120..159  x_3
 *   sp+160..199  z_3
 *   sp+200..239  A
 *   sp+240..279  AA
 *   sp+280..319  B
 *   sp+320..359  BB
 *   sp+360..399  E
 *   sp+400..439  C
 *   sp+440..479  D
 *   sp+480..519  DA
 *   sp+520..559  CB
 *   sp+560..599  TMP   (also the scratch for z_2_inv at the end)
 *   sp+600..619  saved ra, s0..s4
 *   sp+620..639  pad
 *
 * Saved regs:
 *   s0 = loop counter t (start 254, end -1)
 *   s1 = current swap bit (0 or 1)
 *   s2 = caller's out_limbs ptr
 *   s3 = caller's k_bytes ptr
 *   s4 = bit = (swap XOR k_t), preserved across the two cswap calls
 */

        .include "x25519.S"

        .equ X_1,      0
        .equ X_2,     40
        .equ Z_2,     80
        .equ X_3,    120
        .equ Z_3,    160
        .equ A_OFF,  200
        .equ AA,     240
        .equ B_OFF,  280
        .equ BB,     320
        .equ E_OFF,  360
        .equ C_OFF,  400
        .equ D_OFF,  440
        .equ DA,     480
        .equ CB,     520
        .equ TMP,    560
        .equ FRAME,  640
        .equ RA_OFF, 600
        .equ S0_OFF, 604
        .equ S1_OFF, 608
        .equ S2_OFF, 612
        .equ S3_OFF, 616
        .equ S4_OFF, 620

        # COPY_LIMBS dst, src: 10 lw/sw pairs from src ptr to sp+dst.
        .macro COPY_LIMBS dst, src
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4)(\src)
        sw      t0, (\i*4 + \dst)(sp)
        .endr
        .endm

        .macro ZERO_LIMBS dst
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        sw      zero, (\i*4 + \dst)(sp)
        .endr
        .endm

        .macro ONE_LIMBS dst
        li      t0, 1
        sw      t0, (\dst)(sp)
        .irp i, 1, 2, 3, 4, 5, 6, 7, 8, 9
        sw      zero, (\i*4 + \dst)(sp)
        .endr
        .endm

        # Field-op wrappers (stack-relative).
        .macro FADD dst, a, b
        addi    a0, sp, \dst
        addi    a1, sp, \a
        addi    a2, sp, \b
        call    x25519_field_add
        .endm

        .macro FSUB dst, a, b
        addi    a0, sp, \dst
        addi    a1, sp, \a
        addi    a2, sp, \b
        call    x25519_field_sub
        .endm

        .macro FMUL dst, a, b
        addi    a0, sp, \dst
        addi    a1, sp, \a
        addi    a2, sp, \b
        call    x25519_field_mul
        .endm

        .macro FSQ dst, src
        addi    a0, sp, \dst
        addi    a1, sp, \src
        call    x25519_field_sq
        .endm

        .macro FMUL121665 dst, src
        addi    a0, sp, \dst
        addi    a1, sp, \src
        call    x25519_field_mul121665
        .endm

        .macro CSWAP swap_reg, a_off, b_off
        mv      a0, \swap_reg
        addi    a1, sp, \a_off
        addi    a2, sp, \b_off
        call    x25519_cswap
        .endm

        .section .text.x25519_montgomery_ladder, "ax", @progbits
        .global x25519_montgomery_ladder
        .type   x25519_montgomery_ladder, @function
x25519_montgomery_ladder:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        mv      s2, a0                          /* out ptr               */
        mv      s3, a1                          /* k_bytes ptr           */

        # x_1 = u; x_2 = 1, z_2 = 0; x_3 = u, z_3 = 1; swap = 0
        COPY_LIMBS X_1, a2
        ONE_LIMBS  X_2
        ZERO_LIMBS Z_2
        COPY_LIMBS X_3, a2
        ONE_LIMBS  Z_3

        li      s0, 254                         /* t                     */
        li      s1, 0                           /* swap                  */

.Lladder_loop:
        # k_t = (k_bytes[t >> 3] >> (t & 7)) & 1
        srli    t0, s0, 3
        add     t0, s3, t0
        lbu     t0, 0(t0)
        andi    t1, s0, 7
        srl     t0, t0, t1
        andi    t0, t0, 1                       /* t0 = k_t              */

        # bit = swap XOR k_t  (kept in s4 across the two cswap calls)
        xor     s4, s1, t0
        # update saved swap to k_t for next iteration
        mv      s1, t0

        CSWAP   s4, X_2, X_3
        CSWAP   s4, Z_2, Z_3

        # ---- fmonty -------------------------------------------------
        FADD A_OFF, X_2, Z_2                   /* A  = x2 + z2          */
        FSUB B_OFF, X_2, Z_2                   /* B  = x2 - z2          */
        FADD C_OFF, X_3, Z_3                   /* C  = x3 + z3          */
        FSUB D_OFF, X_3, Z_3                   /* D  = x3 - z3          */
        FSQ  AA,    A_OFF                       /* AA = A^2              */
        FSQ  BB,    B_OFF                       /* BB = B^2              */
        FMUL DA,    D_OFF, A_OFF                /* DA = D * A            */
        FMUL CB,    C_OFF, B_OFF                /* CB = C * B            */
        FSUB E_OFF, AA,    BB                   /* E  = AA - BB          */

        # x_3 = (DA + CB)^2
        FADD TMP,   DA,    CB                   /* tmp = DA + CB         */
        FSQ  X_3,   TMP                         /* x_3 = tmp^2           */

        # z_3 = x_1 * (DA - CB)^2
        FSUB TMP,   DA,    CB                   /* tmp = DA - CB         */
        FSQ  TMP,   TMP                         /* tmp = tmp^2           */
        FMUL Z_3,   X_1,   TMP                  /* z_3 = x_1 * tmp       */

        # x_2 = AA * BB
        FMUL X_2,   AA,    BB

        # z_2 = E * (AA + a24 * E)
        FMUL121665 TMP, E_OFF                   /* tmp = a24 * E         */
        FADD TMP,   AA,    TMP                  /* tmp = AA + a24E       */
        FMUL Z_2,   E_OFF, TMP                  /* z_2 = E * tmp         */

        addi    s0, s0, -1
        bgez    s0, .Lladder_loop

        # ---- final cswap ----
        CSWAP   s1, X_2, X_3
        CSWAP   s1, Z_2, Z_3

        # ---- result = x_2 / z_2 = x_2 * z_2^(p-2) ----
        addi    a0, sp, TMP                     /* tmp = z_2^(p-2)       */
        addi    a1, sp, Z_2
        call    x25519_field_inv

        mv      a0, s2                          /* out                   */
        addi    a1, sp, X_2
        addi    a2, sp, TMP
        call    x25519_field_mul

        # ---- restore + return ----
        lw      s4, S4_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   x25519_montgomery_ladder, . - x25519_montgomery_ladder
