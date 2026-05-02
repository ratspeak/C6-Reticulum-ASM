# ============================================================================
# @function:    sha256_final
# @module:      crypto/sha256
# @inputs:      a0 = ctx_ptr, a1 = out_ptr (32-byte buffer for the digest)
# @outputs:     32-byte big-endian SHA-256 digest written at out_ptr; ctx is left in a finalised state (do not call update/final again without re-init)
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s2 (saved+restored across compress)
# @stack:       16
# @cycles:      bounded (~30 + at most 2 × sha256_compress)
# @ct:          required
# @spec:        FIPS 180-4 §5.1.1 (padding); §6.2 (final block)
# @verify:      proofs/crypto/sha256/SHA256Final.cry, proofs/crypto/sha256/sha256_final.saw, proofs/crypto/sha256/sha256_final.py
# @tests:       tests/crypto/sha256/test_sha256_final.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Append the FIPS 180-4 §5.1.1 padding (0x80, then zeros, then 64-bit
 * big-endian length), compress one or two trailing blocks, and write
 * H[0..7] out as 32 big-endian bytes.
 *
 * Padding rule: pad to a multiple of 64 bytes ending in an 8-byte
 * length field. If the appended 0x80 + zeros pushes block_len past
 * byte 56, we emit two trailing blocks; otherwise one.
 *
 * Stack frame (16 bytes):
 *      0..7   s0, s1, s2 + 4 pad
 *         8   (unused)
 *        12   ra
 *
 * Register reservations:
 *   s0 = ctx_ptr  s1 = out_ptr  s2 = scratch (block ptr)
 */

        .include "sha256.S"

        .section .text.sha256_final, "ax", @progbits
        .global sha256_final
        .type   sha256_final, @function
sha256_final:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* ctx_ptr                     */
        mv      s1, a1                  /* out_ptr                     */

        addi    s2, s0, SHA256_CTX_BLOCK   /* &block[0]                */
        lw      t0, SHA256_CTX_BLOCK_LEN(s0)   /* current block_len    */

        /* Append 0x80 at block[block_len++] */
        add     t1, s2, t0
        li      t2, 0x80
        sb      t2, 0(t1)
        addi    t0, t0, 1               /* new block_len               */

        /* If block_len > 56 we need two trailing blocks: pad the
         * current one with zeros to 64, compress, then start a fresh
         * block of all zeros. */
        li      t2, 56
        bleu    t0, t2, .Lpad_zeros

        /* Zero-fill from block[t0] to block[64) */
        add     t1, s2, t0
        li      t3, SHA256_BLOCK_SIZE
        sub     t3, t3, t0              /* zero count                  */
1:      beqz    t3, 2f
        sb      zero, 0(t1)
        addi    t1, t1, 1
        addi    t3, t3, -1
        j       1b
2:      mv      a0, s0
        mv      a1, s2
        call    sha256_compress
        li      t0, 0                   /* fresh block, len = 0        */

.Lpad_zeros:
        /* Zero-fill from block[t0] to block[56) */
        add     t1, s2, t0
        li      t3, 56
        sub     t3, t3, t0
3:      beqz    t3, 4f
        sb      zero, 0(t1)
        addi    t1, t1, 1
        addi    t3, t3, -1
        j       3b

4:      /* Write 64-bit big-endian length_bits at block[56..64).
         * RV32 storage: ctx->length_bits low at offset 32, high at offset 36.
         * BE wire layout: high byte first (bytes 56..59 = high word; bytes 60..63 = low word). */
        addi    t1, s2, 56
        lw      t2, SHA256_CTX_LEN_BITS + 4(s0)   /* high word        */
        srli    t3, t2, 24
        sb      t3, 0(t1)
        srli    t3, t2, 16
        sb      t3, 1(t1)
        srli    t3, t2, 8
        sb      t3, 2(t1)
        sb      t2, 3(t1)
        lw      t2, SHA256_CTX_LEN_BITS(s0)       /* low word         */
        srli    t3, t2, 24
        sb      t3, 4(t1)
        srli    t3, t2, 16
        sb      t3, 5(t1)
        srli    t3, t2, 8
        sb      t3, 6(t1)
        sb      t2, 7(t1)

        /* Compress the final block. */
        mv      a0, s0
        mv      a1, s2
        call    sha256_compress

        /* ---- Emit H[0..7] as 32 big-endian bytes at out_ptr ---- */
        li      t6, 8                   /* word counter                */
        mv      t0, s0                  /* &H[0]                       */
        mv      t1, s1                  /* dst                         */
5:      lw      t2, 0(t0)
        srli    t3, t2, 24
        sb      t3, 0(t1)
        srli    t3, t2, 16
        sb      t3, 1(t1)
        srli    t3, t2, 8
        sb      t3, 2(t1)
        sb      t2, 3(t1)
        addi    t0, t0, 4
        addi    t1, t1, 4
        addi    t6, t6, -1
        bnez    t6, 5b

        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   sha256_final, . - sha256_final
