# ============================================================================
# @function:    lxmf_message_parse
# @module:      lxmf
# @inputs:      a0 = packed message ptr
#               a1 = packed message len
#               a2 = lxmf_message_parsed_t* out
#               a3 = source Ed25519 public key ptr (32 bytes)
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s7
# @stack:       48
# @cycles:      bounded (payload parse + SHA-256 + Ed25519 verify)
# @ct:          not-required
# @spec:        milestone-9 message envelope codec; upstream LXMF/LXMessage.py unpack
# @verify:      proofs/lxmf/lxmf_message_parse.py
# @tests:       tests/lxmf/test_lxmf_message_parse.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Parse and validate the milestone-9 LXMF message subset:
 *
 *   destination_hash || source_hash || signature || payload
 *
 * The payload parser preserves the exact inbound payload bytes and exposes a
 * no-stamp view for message-id/signature validation. The caller supplies the
 * recalled source Ed25519 public key; unknown-source handling belongs to the
 * later inbound dispatch layer.
 */

        .include "lxmf.S"

        .equ LMR_S0_OFF,  0
        .equ LMR_S1_OFF,  4
        .equ LMR_S2_OFF,  8
        .equ LMR_S3_OFF,  12
        .equ LMR_S4_OFF,  16
        .equ LMR_S5_OFF,  20
        .equ LMR_S6_OFF,  24
        .equ LMR_S7_OFF,  28
        .equ LMR_RA_OFF,  44
        .equ LMR_FRAME,   48

        .section .text.lxmf_message_parse, "ax", @progbits
        .global lxmf_message_parse
        .type   lxmf_message_parse, @function
lxmf_message_parse:
        addi    sp, sp, -LMR_FRAME
        sw      s0, LMR_S0_OFF(sp)
        sw      s1, LMR_S1_OFF(sp)
        sw      s2, LMR_S2_OFF(sp)
        sw      s3, LMR_S3_OFF(sp)
        sw      s4, LMR_S4_OFF(sp)
        sw      s5, LMR_S5_OFF(sp)
        sw      s6, LMR_S6_OFF(sp)
        sw      s7, LMR_S7_OFF(sp)
        sw      ra, LMR_RA_OFF(sp)

        mv      s0, a0                  /* packed message ptr           */
        mv      s1, a1                  /* packed message len           */
        mv      s2, a2                  /* parsed output                */
        mv      s3, a3                  /* source public key            */

        beqz    s0, .Llmr_invalid
        beqz    s2, .Llmr_invalid
        beqz    s3, .Llmr_invalid

        li      t0, LXMF_PACKED_PREFIX_SIZE
        bltu    s1, t0, .Llmr_short
        sub     s4, s1, t0              /* payload len                  */

        addi    s5, s2, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PARSED
        addi    a0, s0, LXMF_PACKED_PREFIX_SIZE
        mv      a1, s4
        mv      a2, s5
        call    lxmf_payload_parse
        bnez    a0, .Llmr_done

        sw      s0, LXMF_MESSAGE_PARSED_OFF_DEST_HASH_PTR(s2)
        addi    t0, s0, LXMF_HASH_SIZE
        sw      t0, LXMF_MESSAGE_PARSED_OFF_SOURCE_HASH_PTR(s2)
        addi    t0, s0, LXMF_SIGNING_PREFIX_SIZE
        sw      t0, LXMF_MESSAGE_PARSED_OFF_SIGNATURE_PTR(s2)
        addi    t0, s0, LXMF_PACKED_PREFIX_SIZE
        sw      t0, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PTR(s2)
        sw      s4, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_LEN(s2)

        lw      s6, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR(s5)
        lw      s7, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN(s5)
        sw      s6, LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_PTR(s2)
        sw      s7, LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_LEN(s2)

        mv      a0, s0
        addi    a1, s0, LXMF_HASH_SIZE
        mv      a2, s6
        mv      a3, s7
        addi    a4, s2, LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID
        call    lxmf_message_id
        bnez    a0, .Llmr_done

        mv      a0, s0
        addi    a1, s0, LXMF_HASH_SIZE
        mv      a2, s6
        mv      a3, s7
        addi    a4, s0, LXMF_SIGNING_PREFIX_SIZE
        mv      a5, s3
        call    lxmf_message_verify
        bnez    a0, .Llmr_done

        li      a0, LXMF_OK
        j       .Llmr_done

.Llmr_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llmr_done
.Llmr_short:
        li      a0, LXMF_ERR_SHORT

.Llmr_done:
        lw      s0, LMR_S0_OFF(sp)
        lw      s1, LMR_S1_OFF(sp)
        lw      s2, LMR_S2_OFF(sp)
        lw      s3, LMR_S3_OFF(sp)
        lw      s4, LMR_S4_OFF(sp)
        lw      s5, LMR_S5_OFF(sp)
        lw      s6, LMR_S6_OFF(sp)
        lw      s7, LMR_S7_OFF(sp)
        lw      ra, LMR_RA_OFF(sp)
        addi    sp, sp, LMR_FRAME
        ret

        .size   lxmf_message_parse, . - lxmf_message_parse
