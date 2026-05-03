# ============================================================================
# @function:    aes256_cbc_encrypt
# @module:      crypto/aes
# @inputs:      a0 = round_keys ptr (240 bytes)
#               a1 = iv ptr (16 bytes; not modified)
#               a2 = plaintext ptr
#               a3 = length in bytes (must be a multiple of AES_BLOCK_SIZE)
#               a4 = ciphertext ptr (output, may overlap with plaintext)
# @outputs:     ciphertext[i] = AES-256(K, plaintext[i] ^ prev) chained
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s4 (saved/restored), s5..s11
# @stack:       32
# @cycles:      bounded; n_blocks * (16-byte XOR + aes256_encrypt_block)
# @ct:          required (length is structural; encrypt_block is CT)
# @spec:        NIST SP 800-38A §6.2 (CBC mode)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes256_cbc_encrypt.bsc
# @tests:       tests/crypto/aes/test_aes256_cbc.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES-256-CBC encrypt:
 *
 *   prev = IV
 *   for each block i:
 *       buf = plaintext[i] ^ prev          (16-byte XOR)
 *       ciphertext[i] = AES-256(K, buf)
 *       prev = &ciphertext[i]              (pointer-only; no copy)
 *
 * The XOR scratch is the static aes_block_buf (16 bytes). prev is
 * carried as a *pointer*, starting at the caller's IV and then aliased
 * to the just-written ciphertext block — this avoids an IV copy and
 * keeps the inner loop tight.
 *
 * If a3 == 0, returns immediately with no side effects.
 *
 * Stack layout (32 bytes): ra + s0..s4.
 */

        .include "aes.S"

        .section .text.aes256_cbc_encrypt, "ax", @progbits
        .global aes256_cbc_encrypt
        .type   aes256_cbc_encrypt, @function
aes256_cbc_encrypt:
        beqz    a3, .Lcbc_enc_done

        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)
        sw      s2, 16(sp)
        sw      s3, 12(sp)
        sw      s4, 8(sp)

        mv      s0, a0                  /* round_keys */
        mv      s1, a2                  /* plaintext cursor */
        mv      s2, a4                  /* ciphertext cursor */
        add     s3, a2, a3              /* plaintext end */
        mv      s4, a1                  /* prev (initially IV) */

.Lcbc_enc_loop:
        /* aes_block_buf = plaintext[i] ^ prev (4 word XORs) */
        la      t0, aes_block_buf
        lw      t1, 0(s1)
        lw      t2, 0(s4)
        xor     t1, t1, t2
        sw      t1, 0(t0)
        lw      t1, 4(s1)
        lw      t2, 4(s4)
        xor     t1, t1, t2
        sw      t1, 4(t0)
        lw      t1, 8(s1)
        lw      t2, 8(s4)
        xor     t1, t1, t2
        sw      t1, 8(t0)
        lw      t1, 12(s1)
        lw      t2, 12(s4)
        xor     t1, t1, t2
        sw      t1, 12(t0)

        /* Encrypt aes_block_buf into ciphertext[i] */
        mv      a0, s0
        la      a1, aes_block_buf
        mv      a2, s2
        call    aes256_encrypt_block

        /* prev <- &ciphertext[i] (still in s2 — set as alias for next iter) */
        mv      s4, s2

        addi    s1, s1, AES_BLOCK_SIZE
        addi    s2, s2, AES_BLOCK_SIZE
        bltu    s1, s3, .Lcbc_enc_loop

        lw      ra, 28(sp)
        lw      s0, 24(sp)
        lw      s1, 20(sp)
        lw      s2, 16(sp)
        lw      s3, 12(sp)
        lw      s4, 8(sp)
        addi    sp, sp, 32
.Lcbc_enc_done:
        ret

        .size   aes256_cbc_encrypt, . - aes256_cbc_encrypt
