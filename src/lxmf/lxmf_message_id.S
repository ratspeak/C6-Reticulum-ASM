# ============================================================================
# @function:    lxmf_message_id
# @module:      lxmf
# @inputs:      a0 = destination hash ptr (16 bytes)
#               a1 = source hash ptr (16 bytes)
#               a2 = payload_without_stamp ptr
#               a3 = payload_without_stamp len
#               a4 = out message_id ptr (32 bytes)
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s4
# @stack:       144
# @cycles:      bounded (SHA-256 over <= 429 bytes)
# @ct:          required
# @spec:        milestone-9 message id; upstream LXMF/LXMessage.py hashed_part
# @verify:      proofs/lxmf/lxmf_message_id.py
# @tests:       tests/lxmf/test_lxmf_message_id.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Compute the LXMF message id:
 *
 *   SHA256(destination_hash || source_hash || payload_without_stamp)
 *
 * Upstream `LXMessage.unpack_from_bytes()` removes an optional payload stamp by
 * repacking the first four payload elements before computing this hash. That
 * normalisation is owned by lxmf_payload_parse; this helper hashes the exact
 * bytes supplied by its caller.
 */

        .include "lxmf.S"
        .include "sha256.S"

        .equ LMI_CTX_OFF,  0
        .equ LMI_S0_OFF,   112
        .equ LMI_S1_OFF,   116
        .equ LMI_S2_OFF,   120
        .equ LMI_S3_OFF,   124
        .equ LMI_S4_OFF,   128
        .equ LMI_RA_OFF,   140
        .equ LMI_FRAME,    144

        .section .text.lxmf_message_id, "ax", @progbits
        .global lxmf_message_id
        .type   lxmf_message_id, @function
lxmf_message_id:
        addi    sp, sp, -LMI_FRAME
        sw      s0, LMI_S0_OFF(sp)
        sw      s1, LMI_S1_OFF(sp)
        sw      s2, LMI_S2_OFF(sp)
        sw      s3, LMI_S3_OFF(sp)
        sw      s4, LMI_S4_OFF(sp)
        sw      ra, LMI_RA_OFF(sp)

        mv      s0, a0                  /* destination hash ptr         */
        mv      s1, a1                  /* source hash ptr              */
        mv      s2, a2                  /* payload_without_stamp ptr    */
        mv      s3, a3                  /* payload_without_stamp len    */
        mv      s4, a4                  /* out message_id ptr           */

        beqz    s0, .Llmi_invalid
        beqz    s1, .Llmi_invalid
        beqz    s2, .Llmi_invalid
        beqz    s3, .Llmi_invalid
        beqz    s4, .Llmi_invalid
        li      t0, LXMF_PAYLOAD_MAX_LEN
        bltu    t0, s3, .Llmi_overflow

        addi    a0, sp, LMI_CTX_OFF
        call    sha256_init

        addi    a0, sp, LMI_CTX_OFF
        mv      a1, s0
        li      a2, LXMF_HASH_SIZE
        call    sha256_update

        addi    a0, sp, LMI_CTX_OFF
        mv      a1, s1
        li      a2, LXMF_HASH_SIZE
        call    sha256_update

        addi    a0, sp, LMI_CTX_OFF
        mv      a1, s2
        mv      a2, s3
        call    sha256_update

        addi    a0, sp, LMI_CTX_OFF
        mv      a1, s4
        call    sha256_final

        li      a0, LXMF_OK
        j       .Llmi_done

.Llmi_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llmi_done

.Llmi_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Llmi_done:
        lw      s0, LMI_S0_OFF(sp)
        lw      s1, LMI_S1_OFF(sp)
        lw      s2, LMI_S2_OFF(sp)
        lw      s3, LMI_S3_OFF(sp)
        lw      s4, LMI_S4_OFF(sp)
        lw      ra, LMI_RA_OFF(sp)
        addi    sp, sp, LMI_FRAME
        ret

        .size   lxmf_message_id, . - lxmf_message_id
