# ============================================================================
# @function:    hmac_sha256
# @module:      crypto/hmac
# @inputs:      a0 = key_ptr, a1 = key_len, a2 = msg_ptr, a3 = msg_len, a4 = out_ptr (32 bytes)
# @outputs:     32-byte HMAC-SHA-256 tag written at out_ptr
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s5 (saved+restored)
# @stack:       32
# @cycles:      bounded (~2 × sha256(64 + msg_len) + 64-byte XOR + key prep)
# @ct:          required
# @spec:        RFC 2104 §2 (HMAC); RFC 4231 §4 (test vectors)
# @verify:      proofs/crypto/hmac/HMACSHA256.cry, proofs/crypto/hmac/hmac_sha256.saw, proofs/crypto/hmac/hmac_sha256.py
# @tests:       tests/crypto/hmac/test_hmac_sha256.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* HMAC-SHA-256 per RFC 2104:
 *
 *   K' = SHA-256(K)            if |K| > 64
 *      = K  (zero-padded)      otherwise
 *   tag = SHA-256( (K' XOR opad) || SHA-256( (K' XOR ipad) || msg ) )
 *
 * State reuse: the singleton sha256_ctx is used sequentially for inner
 * then outer (no parallel hashes). hmac_key_prep holds K′; we XOR it
 * with ipad in place, run the inner SHA-256, then XOR with
 * (ipad ^ opad) = 0x6A in place to convert it to (K′ XOR opad), and
 * run the outer SHA-256.
 *
 * Constant-time: the only data-dependent branches are on key_len and
 * msg_len, both of which are non-secret in HMAC's threat model.
 *
 * Stack frame (32 bytes):
 *   0..23  s0..s5  (6 × 4)
 *   24..27 (pad)
 *   28     ra
 */

        .include "sha256.S"
        .include "hmac.S"

        .section .text.hmac_sha256, "ax", @progbits
        .global hmac_sha256
        .type   hmac_sha256, @function
hmac_sha256:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s5, 20(sp)
        sw      s4, 16(sp)
        sw      s3, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* key_ptr     */
        mv      s1, a1                  /* key_len     */
        mv      s2, a2                  /* msg_ptr     */
        mv      s3, a3                  /* msg_len     */
        mv      s4, a4                  /* out_ptr     */

        /* ---- 1. Prepare K′ in hmac_key_prep[0..63] ----
         * If key_len > 64: K' = SHA-256(key); zero bytes 32..63.
         * Else:           copy key bytes; zero bytes key_len..63. */
        li      t0, HMAC_BLOCK_SIZE
        bgtu    s1, t0, .Lhash_long_key

        /* Short key path: byte-copy key into hmac_key_prep, then zero pad. */
        la      t0, hmac_key_prep
        mv      t1, s0
        mv      t2, s1
1:      beqz    t2, 2f
        lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       1b
2:      la      t1, hmac_key_prep
        addi    t1, t1, HMAC_BLOCK_SIZE
3:      beq     t0, t1, .Lipad_xor
        sb      zero, 0(t0)
        addi    t0, t0, 1
        j       3b

.Lhash_long_key:
        /* Long key path: K' = SHA-256(key) (32 bytes), zero-pad to 64. */
        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        mv      a1, s0
        mv      a2, s1
        call    sha256_update
        la      a0, sha256_ctx
        la      a1, hmac_key_prep
        call    sha256_final
        la      t0, hmac_key_prep
        addi    t0, t0, HMAC_TAG_SIZE
        li      t1, HMAC_BLOCK_SIZE - HMAC_TAG_SIZE   /* 32 zeros        */
4:      beqz    t1, .Lipad_xor
        sb      zero, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       4b

.Lipad_xor:
        /* ---- 2. hmac_key_prep[i] ^= 0x36 (in place; K' → K' XOR ipad) ---- */
        la      t0, hmac_key_prep
        li      t1, HMAC_BLOCK_SIZE
        li      t2, HMAC_IPAD_BYTE
5:      beqz    t1, .Linner
        lbu     t3, 0(t0)
        xor     t3, t3, t2
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       5b

.Linner:
        /* ---- 3. inner_tag = SHA-256( (K' XOR ipad) || msg ) ---- */
        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        la      a1, hmac_key_prep
        li      a2, HMAC_BLOCK_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        mv      a1, s2
        mv      a2, s3
        call    sha256_update
        la      a0, sha256_ctx
        la      a1, hmac_inner_tag
        call    sha256_final

        /* ---- 4. hmac_key_prep[i] ^= 0x6A (ipad ^ opad → opad-shaped) ---- */
        la      t0, hmac_key_prep
        li      t1, HMAC_BLOCK_SIZE
        li      t2, HMAC_IPAD_XOR_OPAD
6:      beqz    t1, .Louter
        lbu     t3, 0(t0)
        xor     t3, t3, t2
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       6b

.Louter:
        /* ---- 5. tag = SHA-256( (K' XOR opad) || inner_tag ) ---- */
        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        la      a1, hmac_key_prep
        li      a2, HMAC_BLOCK_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        la      a1, hmac_inner_tag
        li      a2, HMAC_TAG_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        mv      a1, s4
        call    sha256_final

        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 20(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   hmac_sha256, . - hmac_sha256
