# ============================================================================
# @function:    transport_process_announce
# @module:      transport
# @inputs:      a0 = raw packet ptr, a1 = raw packet len, a2 = interface_id
# @outputs:     a0 = 0 for new accepted path, 1 for existing path update, -1 on invalid/rejected announce
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s4
# @stack:       336
# @cycles:      bounded (~24000000)
# @ct:          not-required
# @spec:        milestone-5 transport_process_announce
# @verify:      proofs/transport/process_announce.py, proofs/transport/transport_state.tla
# @tests:       tests/transport/test_process_announce.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Process a raw inbound HEADER_1/HEADER_2 announce into the transport path table
 * and cache a byte-exact path-response packet for later Reticulum path requests.
 */

        .include "announce.S"
        .include "packet.S"
        .include "transport.S"

        .equ TPA_PARSED_OFF, 0
        .equ TPA_ENTRY_OFF,  180
        .equ TPA_S0_OFF,    300
        .equ TPA_S1_OFF,    304
        .equ TPA_S2_OFF,    308
        .equ TPA_S3_OFF,    312
        .equ TPA_S4_OFF,    316
        .equ TPA_RA_OFF,    332
        .equ TPA_FRAME,     336

        .section .text.transport_process_announce, "ax", @progbits
        .global transport_process_announce
        .type   transport_process_announce, @function
transport_process_announce:
        addi    sp, sp, -TPA_FRAME
        sw      s0, TPA_S0_OFF(sp)
        sw      s1, TPA_S1_OFF(sp)
        sw      s2, TPA_S2_OFF(sp)
        sw      s3, TPA_S3_OFF(sp)
        sw      s4, TPA_S4_OFF(sp)
        sw      ra, TPA_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        mv      s2, a2                  /* interface_id                */
        beqz    s0, .Ltpa_invalid

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, TPA_PARSED_OFF
        call    announce_parse
        bnez    a0, .Ltpa_invalid

        addi    a0, sp, TPA_PARSED_OFF
        call    announce_validate
        bnez    a0, .Ltpa_invalid

        addi    a0, sp, TPA_PARSED_OFF + ANNOUNCE_RX_OFF_DEST_HASH
        addi    a1, sp, TPA_ENTRY_OFF
        call    transport_path_lookup
        li      s3, TRANSPORT_STATUS_ACCEPTED
        li      t0, TRANSPORT_ERR_NOT_FOUND
        beq     a0, t0, .Ltpa_update
        bnez    a0, .Ltpa_invalid
        li      s3, TRANSPORT_STATUS_UPDATED

.Ltpa_update:
        addi    a0, sp, TPA_PARSED_OFF
        mv      a1, s2
        lbu     s4, ANNOUNCE_RAW_OFF_HOPS(s0)
        addi    s4, s4, 1
        mv      a2, s4
        lbu     t0, ANNOUNCE_RAW_OFF_FLAGS(s0)
        andi    t0, t0, FLAG_HEADER_TYPE
        beqz    t0, .Ltpa_h1_next_hop
        addi    a3, s0, ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID
        j       .Ltpa_next_hop_ready
.Ltpa_h1_next_hop:
        addi    a3, sp, TPA_PARSED_OFF + ANNOUNCE_RX_OFF_DEST_HASH
.Ltpa_next_hop_ready:
        call    transport_path_update
        bnez    a0, .Ltpa_invalid

        mv      a0, s0
        mv      a1, s1
        mv      a2, s4
        call    transport_path_response_cache_update

        mv      a0, s3
        j       .Ltpa_return

.Ltpa_invalid:
        li      a0, TRANSPORT_ERR_INVAL

.Ltpa_return:
        lw      s0, TPA_S0_OFF(sp)
        lw      s1, TPA_S1_OFF(sp)
        lw      s2, TPA_S2_OFF(sp)
        lw      s3, TPA_S3_OFF(sp)
        lw      s4, TPA_S4_OFF(sp)
        lw      ra, TPA_RA_OFF(sp)
        addi    sp, sp, TPA_FRAME
        ret

        .size   transport_process_announce, . - transport_process_announce
