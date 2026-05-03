# ============================================================================
# @function:    sha512_update
# @module:      crypto/sha512
# @inputs:      a0 = ctx_ptr, a1 = data_ptr, a2 = data_len (bytes; ≤ 2^32 − 1)
# @outputs:     ctx state advanced by `data_len` bytes; full 128-byte
#               blocks are compressed in place
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s5 (saved+restored across compress)
# @stack:       32
# @cycles:      bounded (~6 + 128 cycles per buffered byte + N × sha512_compress)
# @ct:          required
# @spec:        FIPS 180-4 §5.2 (message length); §6.4 (block iteration)
# @verify:      proofs/crypto/sha512/SHA512Update.cry, proofs/crypto/sha512/sha512_update.saw
# @tests:       tests/crypto/sha512/test_sha512_kat.py
#               (Tier A: SAW + Cryptol prove (i) the partial-block
#               post-condition for "abc" (block_len=3, length_bits=24,
#               H unchanged), (ii) the full-block post-condition for
#               128 zero bytes (one compress, length_bits=1024), and
#               (iii) streaming associativity for small chunkings.
#               Tier C bridge: the QEMU pytest cross-checks the asm
#               against hashlib.sha512 across all padding regimes.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Same shape as sha256_update but with 128-byte blocks. The 128-bit
 * length tracking required by FIPS 180-4 is collapsed to a 64-bit
 * counter here — the high 64 bits of the spec's 128-bit length are
 * implicitly zero (caller would have to feed > 2^64 bits = > 2 zetta-
 * bytes for that to overflow, which is not achievable on this class
 * of device). The high 64 bits are still emitted as zero by
 * sha512_final, preserving wire compatibility with FIPS 180-4.
 */

        .include "sha512.S"

        .section .text.sha512_update, "ax", @progbits
        .global sha512_update
        .type   sha512_update, @function
sha512_update:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s5, 24(sp)
        sw      s4, 16(sp)
        sw      s3, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                          /* ctx_ptr                */
        mv      s1, a1                          /* data_ptr               */
        mv      s2, a2                          /* remaining bytes        */

        /* ---- 1. length_bits += data_len * 8 (64-bit accumulate) ---- */
        slli    t0, a2, 3                       /* low 32 of (len*8)      */
        srli    t1, a2, 29                      /* bits 32..34            */
        lw      t2, SHA512_CTX_LEN_BITS(s0)
        lw      t3, SHA512_CTX_LEN_BITS + 4(s0)
        add     t4, t2, t0
        sltu    t5, t4, t2
        add     t3, t3, t1
        add     t3, t3, t5
        sw      t4, SHA512_CTX_LEN_BITS(s0)
        sw      t3, SHA512_CTX_LEN_BITS + 4(s0)

        /* ---- 2. Drain partial block ---- */
        lw      s3, SHA512_CTX_BLOCK_LEN(s0)
        beqz    s3, .Lwhole_blocks_512

        li      t0, SHA512_BLOCK_SIZE
        sub     t0, t0, s3                      /* free bytes in buffer   */
        bgeu    s2, t0, 1f
        mv      t0, s2
1:      addi    t1, s0, SHA512_CTX_BLOCK
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
3:      add     s3, s3, t0
        add     s1, s1, t0
        sub     s2, s2, t0

        li      t0, SHA512_BLOCK_SIZE
        bne     s3, t0, .Lstore_bl_512
        mv      a0, s0
        addi    a1, s0, SHA512_CTX_BLOCK
        call    sha512_compress
        li      s3, 0

.Lwhole_blocks_512:
.Lwblk_512:
        li      t0, SHA512_BLOCK_SIZE
        bltu    s2, t0, .Lbuffer_tail_512
        mv      a0, s0
        mv      a1, s1
        call    sha512_compress
        addi    s1, s1, SHA512_BLOCK_SIZE
        addi    s2, s2, -SHA512_BLOCK_SIZE
        j       .Lwblk_512

.Lbuffer_tail_512:
        beqz    s2, .Lstore_bl_512
        addi    t1, s0, SHA512_CTX_BLOCK
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

.Lstore_bl_512:
        sw      s3, SHA512_CTX_BLOCK_LEN(s0)

        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   sha512_update, . - sha512_update
