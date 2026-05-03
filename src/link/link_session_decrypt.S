# ============================================================================
# @function:    link_session_decrypt
# @module:      link
# @inputs:      a0 = link entry ptr
#               a1 = token ptr
#               a2 = token len
#               a3 = plaintext out ptr
#               a4 = plaintext out capacity
# @outputs:     a0 = plaintext length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s9
# @stack:       80
# @cycles:      bounded (<= 480-byte token, 27 AES-CBC blocks)
# @ct:          required
# @spec:        milestone-6 link_session_decrypt; authenticate before plaintext release
# @verify:      proofs/link/link_session_token.py
# @tests:       tests/link/test_link_session_token.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Reticulum Token-compatible AES-256-CBC session decryption.
 *
 * The HMAC is verified over IV || ciphertext before AES decryption. Decrypted
 * padded plaintext is held in link_session_scratch; bytes are copied to the
 * caller only after authentication and PKCS7 padding validation.
 */

        .include "link.S"
        .include "aes.S"
        .include "hmac.S"

        .equ LSD_TAG_OFF,  0       /* 32-byte expected HMAC tag       */
        .equ LSD_S0_OFF,   32
        .equ LSD_S1_OFF,   36
        .equ LSD_S2_OFF,   40
        .equ LSD_S3_OFF,   44
        .equ LSD_S4_OFF,   48
        .equ LSD_S5_OFF,   52
        .equ LSD_S6_OFF,   56
        .equ LSD_S7_OFF,   60
        .equ LSD_S8_OFF,   64
        .equ LSD_S9_OFF,   68
        .equ LSD_RA_OFF,   76
        .equ LSD_FRAME,    80

        .section .text.link_session_decrypt, "ax", @progbits
        .global link_session_decrypt
        .type   link_session_decrypt, @function
link_session_decrypt:
        addi    sp, sp, -LSD_FRAME
        sw      s0, LSD_S0_OFF(sp)
        sw      s1, LSD_S1_OFF(sp)
        sw      s2, LSD_S2_OFF(sp)
        sw      s3, LSD_S3_OFF(sp)
        sw      s4, LSD_S4_OFF(sp)
        sw      s5, LSD_S5_OFF(sp)
        sw      s6, LSD_S6_OFF(sp)
        sw      s7, LSD_S7_OFF(sp)
        sw      s8, LSD_S8_OFF(sp)
        sw      s9, LSD_S9_OFF(sp)
        sw      ra, LSD_RA_OFF(sp)

        mv      s0, a0                  /* link entry                  */
        mv      s1, a1                  /* token                       */
        mv      s2, a2                  /* token len                   */
        mv      s3, a3                  /* plaintext out               */
        mv      s4, a4                  /* plaintext out capacity      */

        beqz    s0, .Llsd_invalid
        beqz    s1, .Llsd_invalid
        beqz    s3, .Llsd_invalid
        lbu     t0, LINK_ENTRY_OFF_VALID(s0)
        li      t1, 1
        bne     t0, t1, .Llsd_invalid
        lbu     t0, LINK_ENTRY_OFF_STATUS(s0)
        li      t1, LINK_STATUS_ESTABLISHED
        bne     t0, t1, .Llsd_invalid
        lbu     t0, LINK_ENTRY_OFF_MODE(s0)
        li      t1, LINK_MODE_AES256_CBC
        bne     t0, t1, .Llsd_invalid

        li      t0, LINK_SESSION_TOKEN_OVERHEAD + 16
        bltu    s2, t0, .Llsd_invalid
        li      t0, LINK_SESSION_TOKEN_MAX
        bltu    t0, s2, .Llsd_invalid

        addi    s5, s2, -LINK_SESSION_TOKEN_OVERHEAD
        beqz    s5, .Llsd_invalid
        andi    t0, s5, 15
        bnez    t0, .Llsd_invalid
        addi    s6, s2, -HMAC_TAG_SIZE  /* signed part length          */

        addi    a0, s0, LINK_ENTRY_OFF_KEY_MATERIAL
        li      a1, HMAC_TAG_SIZE
        mv      a2, s1
        mv      a3, s6
        addi    a4, sp, LSD_TAG_OFF
        call    hmac_sha256

        addi    a0, sp, LSD_TAG_OFF
        add     a1, s1, s6
        li      a2, HMAC_TAG_SIZE
        call    .Llsd_memeq
        beqz    a0, .Llsd_invalid

        addi    a0, s0, LINK_ENTRY_OFF_KEY_MATERIAL + HMAC_TAG_SIZE
        la      a1, aes_round_keys
        call    aes256_key_expand

        la      s7, link_session_scratch
        la      a0, aes_round_keys
        mv      a1, s1
        addi    a2, s1, LINK_SESSION_IV_SIZE
        mv      a3, s5
        mv      a4, s7
        call    aes256_cbc_decrypt

        add     t0, s7, s5
        addi    t0, t0, -1
        lbu     s8, 0(t0)
        beqz    s8, .Llsd_invalid
        li      t1, 16
        bltu    t1, s8, .Llsd_invalid
        bltu    s5, s8, .Llsd_invalid

        sub     t0, s5, s8
        add     a0, s7, t0
        mv      a1, s8
        mv      a2, s8
        call    .Llsd_check_pad
        beqz    a0, .Llsd_invalid

        sub     s9, s5, s8
        bltu    s4, s9, .Llsd_overflow
        mv      a0, s7
        mv      a1, s3
        mv      a2, s9
        call    .Llsd_copy_bytes
        mv      a0, s9
        j       .Llsd_return

.Llsd_invalid:
        li      a0, LINK_ERR_INVAL
        j       .Llsd_return

.Llsd_overflow:
        li      a0, LINK_ERR_OVERFLOW

.Llsd_return:
        lw      s0, LSD_S0_OFF(sp)
        lw      s1, LSD_S1_OFF(sp)
        lw      s2, LSD_S2_OFF(sp)
        lw      s3, LSD_S3_OFF(sp)
        lw      s4, LSD_S4_OFF(sp)
        lw      s5, LSD_S5_OFF(sp)
        lw      s6, LSD_S6_OFF(sp)
        lw      s7, LSD_S7_OFF(sp)
        lw      s8, LSD_S8_OFF(sp)
        lw      s9, LSD_S9_OFF(sp)
        lw      ra, LSD_RA_OFF(sp)
        addi    sp, sp, LSD_FRAME
        ret

.Llsd_memeq:
        mv      t2, zero
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        lbu     t1, 0(a1)
        xor     t0, t0, t1
        or      t2, t2, t0
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      sltiu   a0, t2, 1
        ret

.Llsd_check_pad:
        mv      t2, zero
        beqz    a1, 4f
3:      lbu     t0, 0(a0)
        xor     t0, t0, a2
        or      t2, t2, t0
        addi    a0, a0, 1
        addi    a1, a1, -1
        bnez    a1, 3b
4:      sltiu   a0, t2, 1
        ret

.Llsd_copy_bytes:
        beqz    a2, 6f
5:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 5b
6:      ret

        .size   link_session_decrypt, . - link_session_decrypt
