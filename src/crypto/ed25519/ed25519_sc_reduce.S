# ============================================================================
# @function:    ed25519_sc_reduce
# @module:      crypto/ed25519
# @inputs:      a0 = out ptr (32 bytes; will receive scalar mod L, LE)
#               a1 = in ptr  (64 bytes; little-endian 512-bit integer)
# @outputs:     out = (in mod L), encoded as 32 LE bytes
# @clobbers:    t0..t6, a2..a7, s0..s5
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       128
# @cycles:      bounded (~512 iterations × ~70 instructions ≈ 36K)
# @ct:          required
# @spec:        Constant-time binary long-division reduction. Maintains
#               the invariant 0 ≤ R < L while shifting bits of `in`
#               (MSB → LSB) into R; conditionally subtracts L (constant-
#               time mask select) when R ≥ L. The bit-by-bit method is
#               slower than Barrett or ref10's 21-bit-limb specialised
#               reduction but it is short, side-channel-clean by
#               construction, and the cost (~36K cycles, ≈ 360µs at
#               100 MHz) is acceptable for sign/verify hot paths since
#               sc_reduce runs at most twice per sign and verify.
# @verify:      proofs/crypto/ed25519/Ed25519Scalar.cry, proofs/crypto/ed25519/ed25519_sc_reduce.saw
# @tests:       tests/crypto/ed25519/test_ed25519_sc_reduce.py
#               (Tier A: SAW + Cryptol prove L_bytes equals the
#               canonical encoding of L = 2^252 + ... and the boundary
#               KATs sc_reduce({0, L, L-1, 2^256, 2^512-1}) match the
#               integer-mod spec. Tier C bridge: the QEMU pytest
#               cross-checks the asm against Python `N mod L` for
#               random inputs in addition to the boundaries.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (128 bytes, 16-byte aligned):
 *      0..31    R[8]            (running remainder, 8 32-bit LE words)
 *     32..63    L[8]            (cached copy of ed25519_L_bytes)
 *     64..95    D[8]            (scratch: diff = R - L per iteration)
 *     96..99    ra
 *    100..123   s0..s5 (6 × 4 = 24 bytes)
 *    124..127   pad
 *
 * Saved regs:
 *   s0 = bit counter (511 → -1)
 *   s1 = in_ptr
 *   s2 = out_ptr
 *   s3 = sp + 0  (R base)
 *   s4 = sp + 32 (L base)
 *   s5 = scratch (running borrow / mask)
 */

        .include "ed25519.S"

        .equ R_OFF,   0
        .equ L_OFF,  32
        .equ D_OFF,  64
        .equ RA_OFF, 96
        .equ S0_OFF, 100
        .equ S1_OFF, 104
        .equ S2_OFF, 108
        .equ S3_OFF, 112
        .equ S4_OFF, 116
        .equ S5_OFF, 120
        .equ FRAME, 128

        .section .text.ed25519_sc_reduce, "ax", @progbits
        .global ed25519_sc_reduce
        .type   ed25519_sc_reduce, @function
ed25519_sc_reduce:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        sw      s5, S5_OFF(sp)

        mv      s1, a1                          /* in_ptr                */
        mv      s2, a0                          /* out_ptr               */
        addi    s3, sp, R_OFF
        addi    s4, sp, L_OFF

        # Zero R.
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        sw      zero, (\i + R_OFF)(sp)
        .endr

        # Cache L.
        la      t0, ed25519_L_bytes
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t1, \i(t0)
        sw      t1, (\i + L_OFF)(sp)
        .endr

        li      s0, 511                         /* bit counter           */

.Lreduce_loop:
        # ---- Step 1: shift R left by 1 (carry chain across 8 words) ----
        # Process bottom → top. Each word: high bit becomes carry-in to next.
        lw      t0, 0(s3)
        lw      t1, 4(s3)
        lw      t2, 8(s3)
        lw      t3, 12(s3)
        lw      t4, 16(s3)
        lw      t5, 20(s3)
        lw      t6, 24(s3)
        lw      a3, 28(s3)

        # Word 7 (high) ← (W7 << 1) | carry_in_from_W6
        srli    a4, t6, 31
        slli    a3, a3, 1
        or      a3, a3, a4

        srli    a4, t5, 31
        slli    t6, t6, 1
        or      t6, t6, a4

        srli    a4, t4, 31
        slli    t5, t5, 1
        or      t5, t5, a4

        srli    a4, t3, 31
        slli    t4, t4, 1
        or      t4, t4, a4

        srli    a4, t2, 31
        slli    t3, t3, 1
        or      t3, t3, a4

        srli    a4, t1, 31
        slli    t2, t2, 1
        or      t2, t2, a4

        srli    a4, t0, 31
        slli    t1, t1, 1
        or      t1, t1, a4

        slli    t0, t0, 1                       /* word 0: no carry-in   */

        # ---- Step 2: insert next bit of `in` at position s0 ----
        srli    a4, s0, 3                       /* byte index            */
        add     a4, s1, a4
        lbu     a4, 0(a4)
        andi    a5, s0, 7
        srl     a4, a4, a5
        andi    a4, a4, 1
        or      t0, t0, a4

        # Save R back.
        sw      t0, 0(s3)
        sw      t1, 4(s3)
        sw      t2, 8(s3)
        sw      t3, 12(s3)
        sw      t4, 16(s3)
        sw      t5, 20(s3)
        sw      t6, 24(s3)
        sw      a3, 28(s3)

        # ---- Step 3: compute D = R - L (with borrow); track final borrow ----
        # Use s5 as the running borrow (0 or 1).
        li      s5, 0

        .macro SUB_WORD i
        lw      t0, (\i + R_OFF)(sp)
        lw      t1, (\i + L_OFF)(sp)
        sub     t2, t0, t1                      /* R - L                  */
        sltu    t3, t0, t1                      /* borrow_a               */
        sub     t4, t2, s5                      /* (R - L) - borrow_in    */
        sltu    t5, t2, s5                      /* borrow_b               */
        or      s5, t3, t5                      /* outgoing borrow        */
        sw      t4, (\i + D_OFF)(sp)
        .endm

        SUB_WORD 0
        SUB_WORD 4
        SUB_WORD 8
        SUB_WORD 12
        SUB_WORD 16
        SUB_WORD 20
        SUB_WORD 24
        SUB_WORD 28

        # mask = (-borrow); 0xFFFFFFFF if R < L (keep R), else 0 (use D).
        sub     s5, zero, s5

        # Constant-time select per word: R[i] = D[i] ^ ((D[i] ^ R[i]) & mask)
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, (\i + R_OFF)(sp)
        lw      t1, (\i + D_OFF)(sp)
        xor     t2, t0, t1
        and     t2, t2, s5
        xor     t1, t1, t2
        sw      t1, (\i + R_OFF)(sp)
        .endr

        # ---- Step 4: bit counter -- ; loop until s0 == -1 ----
        addi    s0, s0, -1
        bgez    s0, .Lreduce_loop

        # ---- Step 5: write R as 32 LE bytes to out ----
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, (\i + R_OFF)(sp)
        sw      t0, \i(s2)
        .endr

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        lw      s5, S5_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_sc_reduce, . - ed25519_sc_reduce
