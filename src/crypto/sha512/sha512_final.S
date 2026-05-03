# ============================================================================
# @function:    sha512_final
# @module:      crypto/sha512
# @inputs:      a0 = ctx_ptr, a1 = out_ptr (64-byte buffer for the digest)
# @outputs:     64-byte big-endian SHA-512 digest written at out_ptr;
#               ctx is left in a finalised state (do not call update/final
#               again without re-init).
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s2 (saved+restored across compress)
# @stack:       16
# @cycles:      bounded (~50 + at most 2 × sha512_compress)
# @ct:          required
# @spec:        FIPS 180-4 §5.1.2 (SHA-512 padding); §6.4 (final block)
# @verify:      proofs/crypto/sha512/SHA512Final.cry, proofs/crypto/sha512/sha512_final.saw
# @tests:       tests/crypto/sha512/test_sha512_kat.py
#               (Tier A: SAW + Cryptol prove four KATs that cover both
#               padding paths — SHA-512("abc") and SHA-512("") for
#               bl ≤ 111 (one trailing block); FIPS 180-4 §C.2 (112
#               bytes) and SHA-512(128 zero bytes) for bl > 111
#               (two trailing blocks). Tier C bridge: the QEMU pytest
#               cross-checks the asm against hashlib.sha512 across
#               just_at_112 / just_above corner cases.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* SHA-512 padding (FIPS 180-4 §5.1.2): append 0x80, then zeros, then a
 * 128-bit big-endian length, padded so the total is a multiple of 128
 * bytes. Length lives in the last 16 bytes; the high 64 bits are zero
 * because the 32-bit data_len input bound makes overflow impossible
 * (caller cannot feed more than 2^32 bytes via a single update, and
 * even ten million such updates won't overflow a 64-bit byte counter).
 *
 * If after the 0x80 the new block_len > 112, we emit two trailing
 * blocks (one to flush the partial, one for the length field);
 * otherwise one.
 *
 * Stack frame (16 bytes):
 *      0..7   s0, s1, s2 + 4 pad
 *         8   (unused)
 *        12   ra
 */

        .include "sha512.S"

        .section .text.sha512_final, "ax", @progbits
        .global sha512_final
        .type   sha512_final, @function
sha512_final:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                          /* ctx_ptr                */
        mv      s1, a1                          /* out_ptr                */

        addi    s2, s0, SHA512_CTX_BLOCK        /* &block[0]              */
        lw      t0, SHA512_CTX_BLOCK_LEN(s0)    /* current block_len      */

        /* Append 0x80 at block[block_len++] */
        add     t1, s2, t0
        li      t2, 0x80
        sb      t2, 0(t1)
        addi    t0, t0, 1

        /* If block_len > 112 (= 128 - 16) we need two trailing blocks. */
        li      t2, 112
        bleu    t0, t2, .Lpad_zeros_512

        /* Zero-fill from block[t0] to block[128); compress; reset. */
        add     t1, s2, t0
        li      t3, SHA512_BLOCK_SIZE
        sub     t3, t3, t0
1:      beqz    t3, 2f
        sb      zero, 0(t1)
        addi    t1, t1, 1
        addi    t3, t3, -1
        j       1b
2:      mv      a0, s0
        mv      a1, s2
        call    sha512_compress
        li      t0, 0

.Lpad_zeros_512:
        /* Zero-fill from block[t0] to block[112) */
        add     t1, s2, t0
        li      t3, 112
        sub     t3, t3, t0
3:      beqz    t3, 4f
        sb      zero, 0(t1)
        addi    t1, t1, 1
        addi    t3, t3, -1
        j       3b

4:      /* Write 128-bit big-endian length_bits at block[112..128).
         * High 64 bits are zero (block[112..119]). The lower 64 bits of
         * the spec's length field map to our 64-bit length_bits at
         * block[120..127]: ctx->length_bits.high → bytes 120..123,
         * ctx->length_bits.low  → bytes 124..127. */
        addi    t1, s2, 112
        # Zero the upper 8 bytes (bytes 112..119).
        sw      zero, 0(t1)
        sw      zero, 4(t1)
        # high word (bytes 120..123)
        lw      t2, SHA512_CTX_LEN_BITS + 4(s0)
        srli    t3, t2, 24
        sb      t3, 8(t1)
        srli    t3, t2, 16
        sb      t3, 9(t1)
        srli    t3, t2, 8
        sb      t3, 10(t1)
        sb      t2, 11(t1)
        # low word (bytes 124..127)
        lw      t2, SHA512_CTX_LEN_BITS(s0)
        srli    t3, t2, 24
        sb      t3, 12(t1)
        srli    t3, t2, 16
        sb      t3, 13(t1)
        srli    t3, t2, 8
        sb      t3, 14(t1)
        sb      t2, 15(t1)

        /* Compress the final block. */
        mv      a0, s0
        mv      a1, s2
        call    sha512_compress

        /* ---- Emit H[0..7] as 64 big-endian bytes at out_ptr ----
         * Each 64-bit H[i] is stored as (lo at +0, hi at +4) in the ctx.
         * BE wire layout: 8 bytes per word, high byte first → high word
         * (offset +4) first, then low word (offset +0). */
        li      t6, 8                           /* word counter           */
        mv      t0, s0                          /* &H[0]                  */
        mv      t1, s1                          /* dst                    */
5:      # high 32 bits → bytes 0..3
        lw      t2, 4(t0)
        srli    t3, t2, 24
        sb      t3, 0(t1)
        srli    t3, t2, 16
        sb      t3, 1(t1)
        srli    t3, t2, 8
        sb      t3, 2(t1)
        sb      t2, 3(t1)
        # low 32 bits → bytes 4..7
        lw      t2, 0(t0)
        srli    t3, t2, 24
        sb      t3, 4(t1)
        srli    t3, t2, 16
        sb      t3, 5(t1)
        srli    t3, t2, 8
        sb      t3, 6(t1)
        sb      t2, 7(t1)

        addi    t0, t0, 8
        addi    t1, t1, 8
        addi    t6, t6, -1
        bnez    t6, 5b

        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   sha512_final, . - sha512_final
