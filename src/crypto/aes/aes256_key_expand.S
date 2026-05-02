# ============================================================================
# @function:    aes256_key_expand
# @module:      crypto/aes
# @inputs:      a0 = key ptr (32 bytes; AES-256 master key)
#               a1 = round_keys ptr (240-byte buffer, 4-byte aligned)
# @outputs:     round_keys[0..239] populated with the 15 round keys
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s4 (saved/restored), s5..s11
# @stack:       32
# @cycles:      bounded (52 iterations + 13 SubWord calls; ~22000)
# @ct:          required (loop count + branch decisions are structural;
#                          aes_subword and xtime are constant-time)
# @spec:        FIPS 197 §5.2 (Key Expansion) for Nk=8, Nb=4, Nr=14
# @verify:      kat-only; full 240-byte schedule checked against FIPS 197 §A.3
# @tests:       tests/crypto/aes/test_aes256_key_expand.py
# @adrs:        0001, 0002, 0006
# @status:      tested
# ============================================================================

/* AES-256 key schedule (FIPS 197 §5.2):
 *
 *   Nk = 8, Nb = 4, Nr = 14, total expanded words = 60 (= 240 bytes).
 *
 *   - First 8 words (32 bytes) of the schedule equal the input key
 *     verbatim.
 *   - For i in [8, 60):
 *       temp = w[i-1]
 *       if i mod 8 == 0:
 *           temp = SubWord(RotWord(temp)) ^ Rcon[i/8]
 *       elif i mod 8 == 4:                 (Nk > 6 case)
 *           temp = SubWord(temp)
 *       w[i] = w[i-8] ^ temp
 *
 * Rcon[r] is a word with the low byte set to 2^(r-1) in GF(2^8) and
 * the upper three bytes zero. For AES-256 we use r = 1..7, so the
 * sequence is 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 — no GF
 * reduction occurs (the first 0x80→0x1B reduction happens at r=9
 * which only AES-192's longer schedule hits within this range, and
 * AES-256 stops at r=7).
 *
 * Stack layout (32 bytes): ra + s0..s4 + 4 bytes pad.
 */

        .include "aes.S"

        .section .text.aes256_key_expand, "ax", @progbits
        .global aes256_key_expand
        .type   aes256_key_expand, @function
aes256_key_expand:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)
        sw      s2, 16(sp)
        sw      s3, 12(sp)
        sw      s4, 8(sp)

        /* Copy 32 bytes from the input key to round_keys[0..31]. */
        lw      t0, 0(a0)
        sw      t0, 0(a1)
        lw      t0, 4(a0)
        sw      t0, 4(a1)
        lw      t0, 8(a0)
        sw      t0, 8(a1)
        lw      t0, 12(a0)
        sw      t0, 12(a1)
        lw      t0, 16(a0)
        sw      t0, 16(a1)
        lw      t0, 20(a0)
        sw      t0, 20(a1)
        lw      t0, 24(a0)
        sw      t0, 24(a1)
        lw      t0, 28(a0)
        sw      t0, 28(a1)

        /* s0 = ptr to w[i-8] (read cursor)
         * s1 = ptr to w[i]   (write cursor; starts at &round_keys[32])
         * s2 = end ptr (= &round_keys[240])
         * s3 = current Rcon byte (starts at 0x01)
         * s4 = i mod 8 (starts at 0 for i=8) */
        addi    s1, a1, AES256_KEY_SIZE
        mv      s0, a1
        addi    s2, a1, AES256_RK_BYTES
        li      s3, 1
        li      s4, 0

.Lke_loop:
        /* temp = w[i-1] */
        lw      t0, -4(s1)

        beqz    s4, .Lke_special_0
        li      t1, 4
        beq     s4, t1, .Lke_special_4
        j       .Lke_combine

.Lke_special_0:
        /* RotWord: cyclic byte left-rotate, == rotr by 8 in
         * little-endian word order. */
        slli    t1, t0, 24
        srli    t0, t0, 8
        or      t0, t0, t1
        /* SubWord */
        mv      a0, t0
        call    aes_subword
        mv      t0, a0
        /* XOR Rcon byte into the low byte. Upper bytes of Rcon are 0. */
        xor     t0, t0, s3
        /* Update Rcon: s3 = xtime(s3). Constant-time, no branch. */
        srli    t1, s3, 7
        neg     t1, t1
        andi    t1, t1, AES_GF_MOD_BYTE
        slli    s3, s3, 1
        andi    s3, s3, 0xff
        xor     s3, s3, t1
        j       .Lke_combine

.Lke_special_4:
        mv      a0, t0
        call    aes_subword
        mv      t0, a0

.Lke_combine:
        /* w[i] = w[i-8] ^ temp */
        lw      t1, 0(s0)
        xor     t0, t0, t1
        sw      t0, 0(s1)

        addi    s0, s0, 4
        addi    s1, s1, 4
        addi    s4, s4, 1
        andi    s4, s4, 7
        bltu    s1, s2, .Lke_loop

        lw      ra, 28(sp)
        lw      s0, 24(sp)
        lw      s1, 20(sp)
        lw      s2, 16(sp)
        lw      s3, 12(sp)
        lw      s4, 8(sp)
        addi    sp, sp, 32
        ret

        .size   aes256_key_expand, . - aes256_key_expand
