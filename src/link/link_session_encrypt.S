# ============================================================================
# @function:    link_session_encrypt
# @module:      link
# @inputs:      a0 = link entry ptr
#               a1 = plaintext ptr
#               a2 = plaintext len
#               a3 = token out ptr
#               a4 = token out capacity
# @outputs:     a0 = token length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s8
# @stack:       48
# @cycles:      bounded (<= 431-byte plaintext, 27 AES-CBC blocks)
# @ct:          required
# @spec:        milestone-6 link_session_encrypt; RNS.Cryptography.Token AES-256-CBC subset
# @verify:      proofs/link/link_session_token.py
# @tests:       tests/link/test_link_session_token.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Reticulum Token-compatible AES-256-CBC session encryption.
 *
 * Derived material layout matches RNS.Cryptography.Token for 64-byte keys:
 *   key_material[0:32]  = HMAC-SHA-256 signing key
 *   key_material[32:64] = AES-256-CBC encryption key
 *
 * Output token:
 *   IV[16] || AES-CBC(PKCS7(plaintext)) || HMAC(signing_key, IV || ct)[32]
 */

        .include "link.S"
        .include "aes.S"
        .include "hmac.S"

        .equ LSE_S0_OFF,   0
        .equ LSE_S1_OFF,   4
        .equ LSE_S2_OFF,   8
        .equ LSE_S3_OFF,   12
        .equ LSE_S4_OFF,   16
        .equ LSE_S5_OFF,   20
        .equ LSE_S6_OFF,   24
        .equ LSE_S7_OFF,   28
        .equ LSE_S8_OFF,   32
        .equ LSE_RA_OFF,   44
        .equ LSE_FRAME,    48

        .section .text.link_session_encrypt, "ax", @progbits
        .global link_session_encrypt
        .type   link_session_encrypt, @function
link_session_encrypt:
        addi    sp, sp, -LSE_FRAME
        sw      s0, LSE_S0_OFF(sp)
        sw      s1, LSE_S1_OFF(sp)
        sw      s2, LSE_S2_OFF(sp)
        sw      s3, LSE_S3_OFF(sp)
        sw      s4, LSE_S4_OFF(sp)
        sw      s5, LSE_S5_OFF(sp)
        sw      s6, LSE_S6_OFF(sp)
        sw      s7, LSE_S7_OFF(sp)
        sw      s8, LSE_S8_OFF(sp)
        sw      ra, LSE_RA_OFF(sp)

        mv      s0, a0                  /* link entry                  */
        mv      s1, a1                  /* plaintext                   */
        mv      s2, a2                  /* plaintext len               */
        mv      s3, a3                  /* token out                   */
        mv      s4, a4                  /* token out capacity          */

        beqz    s0, .Llse_invalid
        beqz    s3, .Llse_invalid
        bnez    s1, .Llse_have_plaintext
        bnez    s2, .Llse_invalid
.Llse_have_plaintext:
        lbu     t0, LINK_ENTRY_OFF_VALID(s0)
        li      t1, 1
        bne     t0, t1, .Llse_invalid
        lbu     t0, LINK_ENTRY_OFF_STATUS(s0)
        li      t1, LINK_STATUS_ESTABLISHED
        bne     t0, t1, .Llse_invalid
        lbu     t0, LINK_ENTRY_OFF_MODE(s0)
        li      t1, LINK_MODE_AES256_CBC
        bne     t0, t1, .Llse_invalid

        li      t0, LINK_SESSION_PLAINTEXT_MAX
        bltu    t0, s2, .Llse_overflow

        andi    t0, s2, 15
        li      s8, 16
        sub     s8, s8, t0              /* PKCS7 pad byte/count        */
        add     s5, s2, s8              /* padded plaintext length     */
        li      t0, LINK_SESSION_TOKEN_OVERHEAD
        add     s6, s5, t0              /* total token length          */
        bltu    s4, s6, .Llse_overflow

        la      s7, link_session_scratch
        mv      a0, s1
        mv      a1, s7
        mv      a2, s2
        call    .Llse_copy_bytes
        add     a0, s7, s2
        mv      a1, s8
        mv      a2, s8
        call    .Llse_fill_bytes

        mv      a0, s3
        li      a1, LINK_SESSION_IV_SIZE
        call    rng_bytes

        addi    a0, s0, LINK_ENTRY_OFF_KEY_MATERIAL + HMAC_TAG_SIZE
        la      a1, aes_round_keys
        call    aes256_key_expand

        la      a0, aes_round_keys
        mv      a1, s3
        mv      a2, s7
        mv      a3, s5
        addi    a4, s3, LINK_SESSION_IV_SIZE
        call    aes256_cbc_encrypt

        addi    t0, s5, LINK_SESSION_IV_SIZE
        addi    a0, s0, LINK_ENTRY_OFF_KEY_MATERIAL
        li      a1, HMAC_TAG_SIZE
        mv      a2, s3
        mv      a3, t0
        add     a4, s3, t0
        call    hmac_sha256

        mv      a0, s6
        j       .Llse_return

.Llse_invalid:
        li      a0, LINK_ERR_INVAL
        j       .Llse_return

.Llse_overflow:
        li      a0, LINK_ERR_OVERFLOW

.Llse_return:
        lw      s0, LSE_S0_OFF(sp)
        lw      s1, LSE_S1_OFF(sp)
        lw      s2, LSE_S2_OFF(sp)
        lw      s3, LSE_S3_OFF(sp)
        lw      s4, LSE_S4_OFF(sp)
        lw      s5, LSE_S5_OFF(sp)
        lw      s6, LSE_S6_OFF(sp)
        lw      s7, LSE_S7_OFF(sp)
        lw      s8, LSE_S8_OFF(sp)
        lw      ra, LSE_RA_OFF(sp)
        addi    sp, sp, LSE_FRAME
        ret

.Llse_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Llse_fill_bytes:
        beqz    a1, 4f
3:      sb      a2, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, -1
        bnez    a1, 3b
4:      ret

        .size   link_session_encrypt, . - link_session_encrypt
