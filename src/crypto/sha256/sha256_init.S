# ============================================================================
# @function:    sha256_init
# @module:      crypto/sha256
# @inputs:      a0 = ctx_ptr (sha256_ctx; 112 bytes, 16-byte aligned, caller-owned)
# @outputs:     ctx->H[0..7] populated with FIPS 180-4 §5.3.3 IVs; ctx->length_bits = 0; ctx->block_len = 0
# @clobbers:    t0, t1, t2, t3
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~30: 8-element copy + 3 zero stores)
# @ct:          required
# @spec:        FIPS 180-4 §5.3.3 (initial hash value)
# @verify:      proofs/crypto/sha256/sha256_init.cry, proofs/crypto/sha256/sha256_init.saw, proofs/crypto/sha256/sha256_init.py
# @tests:       tests/crypto/sha256/test_sha256_init.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Initialise an sha256_ctx in caller-provided memory.
 *
 *   1. Copy the eight FIPS 180-4 §5.3.3 IV words from .rodata into
 *      ctx->H[0..7].
 *   2. Zero the 8-byte length_bits field.
 *   3. Zero the 4-byte block_len field.
 *
 * The 64-byte partial-block buffer is NOT zeroed — it is undefined
 * until block_len > 0, and zeroing it would burn cycles for no
 * security or correctness gain.
 *
 * Constant-time by construction: every memory operation depends only
 * on the ctx pointer (not on any secret). The IV copy is a fixed
 * 8-iteration loop; no data-dependent branches.
 */

        .include "sha256.S"

        .section .text.sha256_init, "ax", @progbits
        .global sha256_init
        .type   sha256_init, @function
sha256_init:
        /* Copy the 8 IV words from .rodata into ctx->H[0..7]. */
        la      t0, sha256_iv
        addi    t1, a0, SHA256_CTX_H
        li      t3, 8                   /* word counter                  */
1:      lw      t2, 0(t0)
        sw      t2, 0(t1)
        addi    t0, t0, 4
        addi    t1, t1, 4
        addi    t3, t3, -1
        bnez    t3, 1b

        /* length_bits = 0 (8 bytes) */
        sw      zero, SHA256_CTX_LEN_BITS(a0)
        sw      zero, SHA256_CTX_LEN_BITS + 4(a0)

        /* block_len = 0 */
        sw      zero, SHA256_CTX_BLOCK_LEN(a0)

        ret

        .size   sha256_init, . - sha256_init
