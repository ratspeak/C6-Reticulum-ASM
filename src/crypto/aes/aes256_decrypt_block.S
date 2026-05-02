# ============================================================================
# @function:    aes256_decrypt_block
# @module:      crypto/aes
# @inputs:      a0 = round_keys ptr (240 bytes; output of aes256_key_expand)
#               a1 = ciphertext ptr (16 bytes)
#               a2 = plaintext ptr (16 bytes; may overlap with ciphertext)
# @outputs:     plaintext[0..15] = AES-256-Decrypt(round_keys, ciphertext)
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s2 (saved/restored), s3..s11
# @stack:       48
# @cycles:      bounded (~75k; 14 inverse rounds + final-round shortcut)
# @ct:          required
# @spec:        FIPS 197 §5.3 (Inverse Cipher) for Nr=14
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw
# @tests:       tests/crypto/aes/test_aes256_decrypt_block.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES-256 inverse cipher (FIPS 197 §5.3):
 *
 *   state = ciphertext
 *   AddRoundKey(state, rk[14])
 *   for r = 13..1:
 *       InvShiftRows(state)
 *       InvSubBytes(state)
 *       AddRoundKey(state, rk[r])
 *       InvMixColumns(state)
 *   InvShiftRows(state)
 *   InvSubBytes(state)
 *   AddRoundKey(state, rk[0])
 *   plaintext = state
 *
 * Stack layout (48 bytes; identical to aes256_encrypt_block):
 *    0..15(sp)   state buffer
 *   16..19(sp)   saved a2 (plaintext destination)
 *   20..23(sp)   pad
 *   24(sp)       saved s0 (round-keys cursor; counts down)
 *   28(sp)       saved s1 (state buffer ptr)
 *   32(sp)       saved s2 (= &rk[0]; loop end)
 *   36..43(sp)   pad
 *   44(sp)       saved ra
 */

        .include "aes.S"

        .equ FSZ,        48
        .equ STATE_OFF,   0
        .equ A2_OFF,     16
        .equ S0_OFF,     24
        .equ S1_OFF,     28
        .equ S2_OFF,     32
        .equ RA_OFF,     44

        .section .text.aes256_decrypt_block, "ax", @progbits
        .global aes256_decrypt_block
        .type   aes256_decrypt_block, @function
aes256_decrypt_block:
        addi    sp, sp, -FSZ
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      a2, A2_OFF(sp)

        /* state[0..15] = ciphertext[0..15] */
        addi    s1, sp, STATE_OFF
        lw      t0, 0(a1)
        sw      t0, 0(s1)
        lw      t0, 4(a1)
        sw      t0, 4(s1)
        lw      t0, 8(a1)
        sw      t0, 8(s1)
        lw      t0, 12(a1)
        sw      t0, 12(s1)

        /* AddRoundKey(state, rk[14]) — start at the last round key.
         * s0 = &rk[14] = round_keys + 224
         * s2 = &rk[0]  = round_keys + 0    (loop end / final-round key) */
        mv      s2, a0
        addi    s0, a0, AES256_RK_BYTES - AES_BLOCK_SIZE
        mv      a0, s1
        mv      a1, s0
        call    aes_addroundkey

        /* Loop r = 13 .. 1: InvShiftRows, InvSubBytes, AddRoundKey,
         * InvMixColumns. */
        addi    s0, s0, -AES_BLOCK_SIZE       /* &rk[13] */

.Ldec_loop:
        mv      a0, s1
        call    aes_invshiftrows
        mv      a0, s1
        call    aes_invsubbytes
        mv      a0, s1
        mv      a1, s0
        call    aes_addroundkey
        mv      a0, s1
        call    aes_invmixcolumns
        addi    s0, s0, -AES_BLOCK_SIZE
        bgtu    s0, s2, .Ldec_loop          /* while s0 > &rk[0] */

        /* Final inverse round (no InvMixColumns); s0 == &rk[0] now. */
        mv      a0, s1
        call    aes_invshiftrows
        mv      a0, s1
        call    aes_invsubbytes
        mv      a0, s1
        mv      a1, s2                       /* &rk[0] */
        call    aes_addroundkey

        /* state → plaintext */
        lw      a2, A2_OFF(sp)
        lw      t0, 0(s1)
        sw      t0, 0(a2)
        lw      t0, 4(s1)
        sw      t0, 4(a2)
        lw      t0, 8(s1)
        sw      t0, 8(a2)
        lw      t0, 12(s1)
        sw      t0, 12(a2)

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        addi    sp, sp, FSZ
        ret

        .size   aes256_decrypt_block, . - aes256_decrypt_block
