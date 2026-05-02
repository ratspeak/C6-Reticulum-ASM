# ============================================================================
# @function:    sha256_update
# @module:      crypto/sha256
# @inputs:      a0 = ctx_ptr, a1 = data_ptr, a2 = data_len (bytes; ≤ 2^32 − 1)
# @outputs:     ctx state advanced by `data_len` bytes; full 64-byte blocks are compressed
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s5 (saved+restored across compress)
# @stack:       32
# @cycles:      bounded (~6 + 64 cycles per buffered byte + N × sha256_compress for N full blocks)
# @ct:          required
# @spec:        FIPS 180-4 §5.2 (message length); §6.2 (block iteration)
# @verify:      proofs/crypto/sha256/SHA256Update.cry, proofs/crypto/sha256/sha256_update.saw, proofs/crypto/sha256/sha256_update.py
# @tests:       tests/crypto/sha256/test_sha256_update.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Append `data_len` bytes to the running hash.
 *
 *   1. Increment ctx->length_bits by data_len * 8 (64-bit).
 *   2. If a partial block is buffered, fill it from `data` and (if it
 *      reaches 64 bytes) compress it.
 *   3. Compress every full 64-byte block remaining in `data`.
 *   4. Buffer the trailing partial block.
 *
 * Constant-time wrt the data contents — the only data-dependent
 * branches are on the length and on the offset into the buffer, both
 * of which are non-secret in the algorithm's threat model.
 *
 * Stack frame (32 bytes):
 *      0..19  s0..s4  (5 × 4 = 20)  + 4 pad
 *         24  s5
 *         28  ra
 *
 * Register reservations across the function:
 *   s0 = ctx_ptr      s1 = data_ptr      s2 = remaining len
 *   s3 = block_len (live count of buffered bytes)
 *   s4 = scratch
 *   s5 = scratch
 */

        .include "sha256.S"

        .section .text.sha256_update, "ax", @progbits
        .global sha256_update
        .type   sha256_update, @function
sha256_update:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s5, 24(sp)
        sw      s4, 16(sp)
        sw      s3, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* ctx_ptr                     */
        mv      s1, a1                  /* data_ptr                    */
        mv      s2, a2                  /* remaining bytes             */

        /* ---- 1. length_bits += data_len * 8 (64-bit accumulate) ---- */
        slli    t0, a2, 3               /* low 32 of (len*8)           */
        srli    t1, a2, 29              /* bits 32..34 of (len*8)      */
        lw      t2, SHA256_CTX_LEN_BITS(s0)
        lw      t3, SHA256_CTX_LEN_BITS + 4(s0)
        add     t4, t2, t0              /* new_lo                      */
        sltu    t5, t4, t2              /* carry                       */
        add     t3, t3, t1
        add     t3, t3, t5              /* new_hi                      */
        sw      t4, SHA256_CTX_LEN_BITS(s0)
        sw      t3, SHA256_CTX_LEN_BITS + 4(s0)

        /* ---- 2. If a partial block is buffered, fill it first ---- */
        lw      s3, SHA256_CTX_BLOCK_LEN(s0)
        beqz    s3, .Lwhole_blocks

        /* n = min(s2, 64 - s3); copy n bytes; advance pointers/len. */
        li      t0, SHA256_BLOCK_SIZE
        sub     t0, t0, s3              /* free bytes in buffer        */
        bgeu    s2, t0, 1f
        mv      t0, s2                  /* n = remaining               */
1:      /* dst = ctx + BLOCK_OFF + s3; src = s1; cnt = t0 */
        addi    t1, s0, SHA256_CTX_BLOCK
        add     t1, t1, s3
        mv      t2, s1
        mv      t3, t0
2:      beqz    t3, 3f
        lbu     t4, 0(t2)
        sb      t4, 0(t1)
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        j       2b
3:      add     s3, s3, t0              /* block_len += n              */
        add     s1, s1, t0              /* data_ptr += n               */
        sub     s2, s2, t0              /* remaining -= n              */

        /* If buffer is now full, compress and reset block_len. */
        li      t0, SHA256_BLOCK_SIZE
        bne     s3, t0, .Lstore_bl
        mv      a0, s0
        addi    a1, s0, SHA256_CTX_BLOCK
        call    sha256_compress
        li      s3, 0

.Lwhole_blocks:
        /* ---- 3. Compress whole 64-byte blocks straight from data ----
         * The block-size constant must be re-loaded each iteration: t0
         * is caller-saved, so sha256_compress is free to clobber it. */
.Lwblk:
        li      t0, SHA256_BLOCK_SIZE
        bltu    s2, t0, .Lbuffer_tail
        mv      a0, s0
        mv      a1, s1
        call    sha256_compress
        addi    s1, s1, SHA256_BLOCK_SIZE
        addi    s2, s2, -SHA256_BLOCK_SIZE
        j       .Lwblk

.Lbuffer_tail:
        /* ---- 4. Buffer the leftover bytes (s2 < 64; s3 == 0 or unchanged) ---- */
        beqz    s2, .Lstore_bl
        addi    t1, s0, SHA256_CTX_BLOCK
        add     t1, t1, s3
        mv      t2, s1
        mv      t3, s2
4:      beqz    t3, 5f
        lbu     t4, 0(t2)
        sb      t4, 0(t1)
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        j       4b
5:      add     s3, s3, s2

.Lstore_bl:
        sw      s3, SHA256_CTX_BLOCK_LEN(s0)

        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   sha256_update, . - sha256_update
