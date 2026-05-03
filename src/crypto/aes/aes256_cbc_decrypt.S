# ============================================================================
# @function:    aes256_cbc_decrypt
# @module:      crypto/aes
# @inputs:      a0 = round_keys ptr (240 bytes)
#               a1 = iv ptr (16 bytes; not modified)
#               a2 = ciphertext ptr
#               a3 = length in bytes (must be a multiple of AES_BLOCK_SIZE)
#               a4 = plaintext ptr (output, may overlap with ciphertext)
# @outputs:     plaintext[i] = AES-256-Decrypt(K, ciphertext[i]) ^ prev
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s3 (saved/restored), s4..s11
# @stack:       32
# @cycles:      bounded; n_blocks * (2 * 16-byte copies + decrypt + XOR)
# @ct:          required
# @spec:        NIST SP 800-38A §6.2 (CBC mode, decryption)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes256_cbc_decrypt.bsc
# @tests:       tests/crypto/aes/test_aes256_cbc.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES-256-CBC decrypt:
 *
 *   prev_buf = IV   (copied once into aes_iv_buf)
 *   for each block i:
 *       saved = ciphertext[i]                     (snapshot to aes_block_buf;
 *                                                   handles in-place aliasing)
 *       plaintext[i] = AES-256-Decrypt(K, saved)
 *       plaintext[i] ^= prev_buf                  (16-byte XOR)
 *       prev_buf = saved                          (copy aes_block_buf
 *                                                   into aes_iv_buf)
 *
 * If a3 == 0, returns immediately.
 *
 * Stack layout (32 bytes): ra + s0..s3 + 4 bytes pad.
 */

        .include "aes.S"

        .section .text.aes256_cbc_decrypt, "ax", @progbits
        .global aes256_cbc_decrypt
        .type   aes256_cbc_decrypt, @function
aes256_cbc_decrypt:
        beqz    a3, .Lcbc_dec_done

        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)
        sw      s2, 16(sp)
        sw      s3, 12(sp)

        mv      s0, a0                  /* round_keys */
        mv      s1, a2                  /* ciphertext cursor */
        mv      s2, a4                  /* plaintext cursor */
        add     s3, a2, a3              /* ciphertext end */

        /* prev_buf = IV (copy 16 bytes from a1 to aes_iv_buf) */
        la      t0, aes_iv_buf
        lw      t1, 0(a1)
        sw      t1, 0(t0)
        lw      t1, 4(a1)
        sw      t1, 4(t0)
        lw      t1, 8(a1)
        sw      t1, 8(t0)
        lw      t1, 12(a1)
        sw      t1, 12(t0)

.Lcbc_dec_loop:
        /* aes_block_buf = ciphertext[i] (snapshot to enable in-place) */
        la      t0, aes_block_buf
        lw      t1, 0(s1)
        sw      t1, 0(t0)
        lw      t1, 4(s1)
        sw      t1, 4(t0)
        lw      t1, 8(s1)
        sw      t1, 8(t0)
        lw      t1, 12(s1)
        sw      t1, 12(t0)

        /* decrypt(rk, aes_block_buf, plaintext[i]) */
        mv      a0, s0
        la      a1, aes_block_buf
        mv      a2, s2
        call    aes256_decrypt_block

        /* plaintext[i] ^= aes_iv_buf */
        la      t0, aes_iv_buf
        lw      t1, 0(s2)
        lw      t2, 0(t0)
        xor     t1, t1, t2
        sw      t1, 0(s2)
        lw      t1, 4(s2)
        lw      t2, 4(t0)
        xor     t1, t1, t2
        sw      t1, 4(s2)
        lw      t1, 8(s2)
        lw      t2, 8(t0)
        xor     t1, t1, t2
        sw      t1, 8(s2)
        lw      t1, 12(s2)
        lw      t2, 12(t0)
        xor     t1, t1, t2
        sw      t1, 12(s2)

        /* aes_iv_buf = aes_block_buf (becomes prev for next iter) */
        la      t0, aes_iv_buf
        la      t1, aes_block_buf
        lw      t2, 0(t1)
        sw      t2, 0(t0)
        lw      t2, 4(t1)
        sw      t2, 4(t0)
        lw      t2, 8(t1)
        sw      t2, 8(t0)
        lw      t2, 12(t1)
        sw      t2, 12(t0)

        addi    s1, s1, AES_BLOCK_SIZE
        addi    s2, s2, AES_BLOCK_SIZE
        bltu    s1, s3, .Lcbc_dec_loop

        lw      ra, 28(sp)
        lw      s0, 24(sp)
        lw      s1, 20(sp)
        lw      s2, 16(sp)
        lw      s3, 12(sp)
        addi    sp, sp, 32
.Lcbc_dec_done:
        ret

        .size   aes256_cbc_decrypt, . - aes256_cbc_decrypt
