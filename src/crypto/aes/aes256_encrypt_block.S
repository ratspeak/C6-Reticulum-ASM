# ============================================================================
# @function:    aes256_encrypt_block
# @module:      crypto/aes
# @inputs:      a0 = round_keys ptr (240 bytes; output of aes256_key_expand)
#               a1 = plaintext ptr (16 bytes)
#               a2 = ciphertext ptr (16 bytes; may overlap with plaintext)
# @outputs:     ciphertext[0..15] = AES-256(round_keys, plaintext)
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s2 (saved/restored), s3..s11
# @stack:       48
# @cycles:      bounded (14 rounds * (subbytes + shiftrows + mixcolumns +
#                        addroundkey) + initial AddRoundKey + final round
#                        without MixColumns; ~70k)
# @ct:          required (every callee is constant-time; loop count is
#                          structural)
# @spec:        FIPS 197 §5.1 (Cipher) for Nr=14
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes256_encrypt_block.bsc
# @tests:       tests/crypto/aes/test_aes256_encrypt_block.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES-256 encrypt one 16-byte block.
 *
 *   state = plaintext
 *   AddRoundKey(state, rk[0])
 *   for r = 1..13:
 *       SubBytes(state)
 *       ShiftRows(state)
 *       MixColumns(state)
 *       AddRoundKey(state, rk[r])
 *   SubBytes(state)
 *   ShiftRows(state)
 *   AddRoundKey(state, rk[14])
 *   ciphertext = state
 *
 * The state lives in a stack-resident scratch buffer so the caller's
 * plaintext is never written through (input/output may safely alias).
 *
 * Stack layout (48 bytes):
 *    0..15(sp)   state buffer
 *   16..19(sp)   saved a2 (ciphertext destination)
 *   20..23(sp)   pad
 *   24(sp)       saved s0 (round-keys cursor)
 *   28(sp)       saved s1 (state buffer ptr)
 *   32(sp)       saved s2 (round-keys end ptr — &rk[14])
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

        .section .text.aes256_encrypt_block, "ax", @progbits
        .global aes256_encrypt_block
        .type   aes256_encrypt_block, @function
aes256_encrypt_block:
        addi    sp, sp, -FSZ
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      a2, A2_OFF(sp)          /* preserve ciphertext dest */

        /* state[0..15] = plaintext[0..15] */
        addi    s1, sp, STATE_OFF       /* state ptr */
        lw      t0, 0(a1)
        sw      t0, 0(s1)
        lw      t0, 4(a1)
        sw      t0, 4(s1)
        lw      t0, 8(a1)
        sw      t0, 8(s1)
        lw      t0, 12(a1)
        sw      t0, 12(s1)

        /* Initial AddRoundKey with rk[0] */
        mv      s0, a0                  /* round-keys cursor at rk[0] */
        addi    s2, a0, AES256_RK_BYTES - AES_BLOCK_SIZE   /* &rk[14] */
        mv      a0, s1
        mv      a1, s0
        call    aes_addroundkey

        /* Rounds 1..13: full mix */
        addi    s0, s0, AES_BLOCK_SIZE  /* &rk[1] */

.Lenc_loop:
        mv      a0, s1
        call    aes_subbytes
        mv      a0, s1
        call    aes_shiftrows
        mv      a0, s1
        call    aes_mixcolumns
        mv      a0, s1
        mv      a1, s0
        call    aes_addroundkey
        addi    s0, s0, AES_BLOCK_SIZE
        bltu    s0, s2, .Lenc_loop

        /* Final round (no MixColumns); s0 now == &rk[14] */
        mv      a0, s1
        call    aes_subbytes
        mv      a0, s1
        call    aes_shiftrows
        mv      a0, s1
        mv      a1, s0
        call    aes_addroundkey

        /* state → ciphertext (caller-supplied) */
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

        .size   aes256_encrypt_block, . - aes256_encrypt_block
