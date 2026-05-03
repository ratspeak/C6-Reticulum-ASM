# ============================================================================
# @function:    link_derive_keys
# @module:      link
# @inputs:      a0 = shared_secret ptr (32 bytes), a1 = transcript/link-id salt ptr, a2 = transcript len, a3 = key_material_out ptr (64 bytes)
# @outputs:     a0 = 0 on success, -1 on invalid input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       64
# @cycles:      bounded (~hkdf_extract + 2 x hkdf_expand blocks)
# @ct:          required
# @spec:        milestone-6 link_derive_keys; upstream RNS.Link AES-256-CBC HKDF length
# @verify:      proofs/link/link_derive_keys.py
# @tests:       tests/link/test_link_derive_keys.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Derive Reticulum link session material for the milestone-6 AES-256-CBC
 * subset:
 *
 *   PRK = HKDF-Extract(salt = transcript/link_id, IKM = shared_secret)
 *   OKM = HKDF-Expand(PRK, info = empty, L = 64)
 *
 * Upstream RNS.Link derives 64 bytes for MODE_AES256_CBC. The caller owns the
 * X25519 exchange and passes the resulting shared secret here.
 */

        .include "link.S"
        .include "hkdf.S"

        .equ LDK_PRK_OFF, 0
        .equ LDK_S0_OFF,  32
        .equ LDK_S1_OFF,  36
        .equ LDK_S2_OFF,  40
        .equ LDK_S3_OFF,  44
        .equ LDK_RA_OFF,  60
        .equ LDK_FRAME,   64

        .section .text.link_derive_keys, "ax", @progbits
        .global link_derive_keys
        .type   link_derive_keys, @function
link_derive_keys:
        addi    sp, sp, -LDK_FRAME
        sw      s0, LDK_S0_OFF(sp)
        sw      s1, LDK_S1_OFF(sp)
        sw      s2, LDK_S2_OFF(sp)
        sw      s3, LDK_S3_OFF(sp)
        sw      ra, LDK_RA_OFF(sp)

        mv      s0, a0                  /* shared_secret              */
        mv      s1, a1                  /* transcript/link-id salt    */
        mv      s2, a2                  /* transcript len             */
        mv      s3, a3                  /* key_material_out           */

        beqz    s0, .Lldk_fail
        beqz    s1, .Lldk_fail
        beqz    s2, .Lldk_fail
        beqz    s3, .Lldk_fail

        /* hkdf_extract(transcript, transcript_len, shared_secret, 32, prk) */
        mv      a0, s1
        mv      a1, s2
        mv      a2, s0
        li      a3, LINK_SHARED_SECRET_SIZE
        addi    a4, sp, LDK_PRK_OFF
        call    hkdf_extract

        /* hkdf_expand(prk, 32, empty-info, 0, key_material_out, 64) */
        addi    a0, sp, LDK_PRK_OFF
        li      a1, LINK_PRK_SIZE
        mv      a2, zero
        li      a3, 0
        mv      a4, s3
        li      a5, LINK_KEY_MATERIAL_SIZE
        call    hkdf_expand

        li      a0, LINK_OK
        j       .Lldk_return

.Lldk_fail:
        li      a0, LINK_ERR_INVAL

.Lldk_return:
        lw      s0, LDK_S0_OFF(sp)
        lw      s1, LDK_S1_OFF(sp)
        lw      s2, LDK_S2_OFF(sp)
        lw      s3, LDK_S3_OFF(sp)
        lw      ra, LDK_RA_OFF(sp)
        addi    sp, sp, LDK_FRAME
        ret

        .size   link_derive_keys, . - link_derive_keys
