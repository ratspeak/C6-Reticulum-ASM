# ============================================================================
# @function:    resource_process_plaintext
# @module:      resource
# @inputs:      a0 = link entry ptr, a1 = packet context byte, a2 = plaintext ptr, a3 = plaintext len
# @outputs:     a0 = stable resource/channel status, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s4
# @stack:       160
# @cycles:      bounded (~431-byte parser plus 2-entry reassembly scan)
# @ct:          not-required
# @spec:        milestone-7 resource_process_plaintext
# @verify:      proofs/resource/resource_process.py, proofs/resource/resource_state.tla
# @tests:       tests/resource/test_resource_process_plaintext.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Dispatch decrypted link plaintext for milestone-7 resource/channel
 * contexts. The link entry pointer is currently a contract anchor for the
 * post-decrypt call site; this bounded subset does not mutate link state.
 */

        .include "resource.S"

        .equ RPP_ENV_OFF,  0
        .equ RPP_ADV_OFF,  24
        .equ RPP_S0_OFF,   128
        .equ RPP_S1_OFF,   132
        .equ RPP_S2_OFF,   136
        .equ RPP_S3_OFF,   140
        .equ RPP_S4_OFF,   144
        .equ RPP_RA_OFF,   156
        .equ RPP_FRAME,    160

        .section .text.resource_process_plaintext, "ax", @progbits
        .global resource_process_plaintext
        .type   resource_process_plaintext, @function
resource_process_plaintext:
        addi    sp, sp, -RPP_FRAME
        sw      s0, RPP_S0_OFF(sp)
        sw      s1, RPP_S1_OFF(sp)
        sw      s2, RPP_S2_OFF(sp)
        sw      s3, RPP_S3_OFF(sp)
        sw      s4, RPP_S4_OFF(sp)
        sw      ra, RPP_RA_OFF(sp)

        mv      s0, a0                  /* link entry ptr              */
        mv      s1, a1                  /* packet context              */
        mv      s2, a2                  /* plaintext ptr               */
        mv      s3, a3                  /* plaintext len               */

        beqz    s0, .Lrpproc_invalid
        beqz    s3, .Lrpproc_check_zero_len
        beqz    s2, .Lrpproc_invalid
        j       .Lrpproc_dispatch

.Lrpproc_check_zero_len:
        beqz    s2, .Lrpproc_dispatch

.Lrpproc_dispatch:
        li      t0, RESOURCE_CONTEXT_CHANNEL
        beq     s1, t0, .Lrpproc_channel
        li      t0, RESOURCE_CONTEXT_RESOURCE_ADV
        beq     s1, t0, .Lrpproc_resource_adv
        li      t0, RESOURCE_CONTEXT_RESOURCE
        beq     s1, t0, .Lrpproc_resource_part
        j       .Lrpproc_invalid

.Lrpproc_channel:
        mv      a0, s2
        mv      a1, s3
        addi    a2, sp, RPP_ENV_OFF
        call    channel_envelope_parse
        bltz    a0, .Lrpproc_done
        li      a0, RESOURCE_PROCESS_STATUS_CHANNEL
        j       .Lrpproc_done

.Lrpproc_resource_adv:
        mv      a0, s2
        mv      a1, s3
        addi    a2, sp, RPP_ADV_OFF
        call    resource_advertisement_parse
        bltz    a0, .Lrpproc_done
        addi    a0, sp, RPP_ADV_OFF
        mv      a1, zero
        mv      a2, zero
        call    resource_reassembly_update
        j       .Lrpproc_done

.Lrpproc_resource_part:
        mv      a0, zero
        mv      a1, s2
        mv      a2, s3
        call    resource_reassembly_update
        j       .Lrpproc_done

.Lrpproc_invalid:
        li      a0, RESOURCE_ERR_INVAL

.Lrpproc_done:
        lw      s0, RPP_S0_OFF(sp)
        lw      s1, RPP_S1_OFF(sp)
        lw      s2, RPP_S2_OFF(sp)
        lw      s3, RPP_S3_OFF(sp)
        lw      s4, RPP_S4_OFF(sp)
        lw      ra, RPP_RA_OFF(sp)
        addi    sp, sp, RPP_FRAME
        ret

        .size   resource_process_plaintext, . - resource_process_plaintext
