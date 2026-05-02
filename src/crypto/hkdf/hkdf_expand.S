# ============================================================================
# @function:    hkdf_expand
# @module:      crypto/hkdf
# @inputs:      a0 = prk_ptr, a1 = prk_len (must be ≥ 32), a2 = info_ptr, a3 = info_len (≤ 223), a4 = okm_out, a5 = okm_len (≤ 255 × 32)
# @outputs:     okm_len bytes of derived key material at okm_out
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s7 (saved+restored)
# @stack:       48
# @cycles:      bounded (ceil(okm_len/32) × HMAC over (32 + info_len + 1) bytes)
# @ct:          required
# @spec:        RFC 5869 §2.3 (Expand)
# @verify:      proofs/crypto/hkdf/HKDFSHA256.cry, proofs/crypto/hkdf/hkdf_expand.saw, proofs/crypto/hkdf/hkdf_expand.py
# @tests:       tests/crypto/hkdf/test_hkdf_expand.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* HKDF-Expand per RFC 5869 §2.3:
 *
 *     N = ceil(L / HashLen)
 *     T(0) = empty
 *     T(i) = HMAC-PRK( T(i-1) || info || i )       for i = 1..N
 *     OKM  = T(1) || T(2) || ... || T(N)           truncated to L bytes
 *
 * Implementation: each iteration assembles `msg = T(i-1) || info ||
 * counter` in `hkdf_msg_buf` and runs hmac_sha256 with output landing
 * in `hkdf_t_buf`. We then copy as many bytes of T(i) into okm_out as
 * still fit in the requested length.
 *
 * Stack frame (48 bytes):
 *     0..27   s0..s6 (7 × 4)
 *        28   pad
 *        32   pad
 *        36   pad
 *        40   pad
 *        44   ra
 *
 * Register reservations across the i-loop:
 *   s0 = prk_ptr      s1 = prk_len
 *   s2 = info_ptr     s3 = info_len
 *   s4 = okm_out (advances)   s5 = okm_remaining
 *   s6 = counter i (1..N)
 */

        .include "hkdf.S"

        .section .text.hkdf_expand, "ax", @progbits
        .global hkdf_expand
        .type   hkdf_expand, @function
hkdf_expand:
        addi    sp, sp, -48
        sw      ra, 44(sp)
        sw      s6, 24(sp)
        sw      s5, 20(sp)
        sw      s4, 16(sp)
        sw      s3, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* prk_ptr      */
        mv      s1, a1                  /* prk_len      */
        mv      s2, a2                  /* info_ptr     */
        mv      s3, a3                  /* info_len     */
        mv      s4, a4                  /* okm_out      */
        mv      s5, a5                  /* okm_remaining*/
        li      s6, 1                   /* i = 1        */

.Liter:
        beqz    s5, .Ldone

        /* Build hkdf_msg_buf: [T(i-1) (if i>1)] || info || counter
         *   t0 = write cursor in hkdf_msg_buf
         *   t1 = source pointer
         *   t2 = remaining bytes to copy
         *   t3 = scratch
         */
        la      t0, hkdf_msg_buf

        /* If i > 1, prepend T(i-1) (32 bytes from hkdf_t_buf). */
        li      t3, 1
        beq     s6, t3, .Lcopy_info
        la      t1, hkdf_t_buf
        li      t2, HKDF_HASH_LEN
1:      lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, 1b

.Lcopy_info:
        /* Append `info` bytes (s3 of them). */
        beqz    s3, .Lcounter
        mv      t1, s2
        mv      t2, s3
2:      lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, 2b

.Lcounter:
        /* Append the 1-byte counter `i`. */
        sb      s6, 0(t0)

        /* HMAC-SHA-256(prk, msg, msg_len) → hkdf_t_buf
         * msg_len = (i==1 ? 0 : 32) + info_len + 1 */
        mv      a0, s0
        mv      a1, s1
        la      a2, hkdf_msg_buf
        li      t3, 1
        beq     s6, t3, 3f
        addi    a3, s3, HKDF_HASH_LEN + 1     /* msg_len with prefix    */
        j       4f
3:      addi    a3, s3, 1                     /* msg_len without prefix */
4:      la      a4, hkdf_t_buf
        call    hmac_sha256

        /* Copy min(32, s5) bytes from hkdf_t_buf to s4; advance s4, s5. */
        li      t3, HKDF_HASH_LEN
        bgeu    s5, t3, 5f
        mv      t3, s5
5:      la      t1, hkdf_t_buf
        mv      t2, t3
6:      lbu     t4, 0(t1)
        sb      t4, 0(s4)
        addi    t1, t1, 1
        addi    s4, s4, 1
        addi    t2, t2, -1
        bnez    t2, 6b
        sub     s5, s5, t3

        addi    s6, s6, 1
        j       .Liter

.Ldone:
        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 20(sp)
        lw      s6, 24(sp)
        lw      ra, 44(sp)
        addi    sp, sp, 48
        ret

        .size   hkdf_expand, . - hkdf_expand
