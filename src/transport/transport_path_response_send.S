# ============================================================================
# @function:    transport_path_response_send
# @module:      transport
# @inputs:      a0 = requested destination hash ptr, a1 = requestor transport id ptr or 0, a2 = interface_id
# @outputs:     a0 = TRANSPORT_STATUS_FORWARDED, TRANSPORT_ERR_*, or LORA_ERR_*
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s7
# @stack:       160
# @cycles:      bounded (path lookup + 8 cache slots + LoRa send)
# @ct:          not-required
# @spec:        minimal LoRa transport path-response sender
# @verify:      proofs/transport/path_response.py
# @tests:       tests/transport/test_path_response.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

/* Answer a Reticulum path request from the learned route table and cached
 * byte-exact announce response. Requests coming from the route's own next hop
 * are suppressed to avoid sending the response back toward the source path.
 */

        .include "lora.S"
        .include "packet.S"
        .include "transport.S"

        .equ TPRS_ENTRY_OFF, 0
        .equ TPRS_S0_OFF,   120
        .equ TPRS_S1_OFF,   124
        .equ TPRS_S2_OFF,   128
        .equ TPRS_S3_OFF,   132
        .equ TPRS_S4_OFF,   136
        .equ TPRS_S5_OFF,   140
        .equ TPRS_S6_OFF,   144
        .equ TPRS_S7_OFF,   148
        .equ TPRS_RA_OFF,   156
        .equ TPRS_FRAME,    160

        .section .text.transport_path_response_send, "ax", @progbits
        .global transport_path_response_send
        .type   transport_path_response_send, @function
transport_path_response_send:
        addi    sp, sp, -TPRS_FRAME
        sw      s0, TPRS_S0_OFF(sp)
        sw      s1, TPRS_S1_OFF(sp)
        sw      s2, TPRS_S2_OFF(sp)
        sw      s3, TPRS_S3_OFF(sp)
        sw      s4, TPRS_S4_OFF(sp)
        sw      s5, TPRS_S5_OFF(sp)
        sw      s6, TPRS_S6_OFF(sp)
        sw      s7, TPRS_S7_OFF(sp)
        sw      ra, TPRS_RA_OFF(sp)

        mv      s0, a0                  /* requested destination hash   */
        mv      s1, a1                  /* requestor transport id       */
        mv      s2, a2                  /* ingress interface id         */
        beqz    s0, .Ltprs_invalid

        li      t0, TRANSPORT_INTERFACE_LORA
        bne     s2, t0, .Ltprs_missing

        mv      a0, s0
        addi    a1, sp, TPRS_ENTRY_OFF
        call    transport_path_lookup
        li      t0, TRANSPORT_ERR_NOT_FOUND
        beq     a0, t0, .Ltprs_missing
        bnez    a0, .Ltprs_invalid

        beqz    s1, .Ltprs_scan_cache
        mv      a0, s1
        addi    a1, sp, TPRS_ENTRY_OFF + TRANSPORT_PATH_OFF_NEXT_HOP
        li      a2, HASH_LEN
        call    .Ltprs_memeq
        bnez    a0, .Ltprs_missing

.Ltprs_scan_cache:
        la      s3, transport_path_response_cache
        li      s4, TRANSPORT_PATH_RESPONSE_CAPACITY
.Ltprs_scan_slot:
        beqz    s4, .Ltprs_missing
        lbu     t0, TRANSPORT_PATH_RESPONSE_OFF_VALID(s3)
        beqz    t0, .Ltprs_next_slot

        mv      a0, s0
        addi    a1, s3, TRANSPORT_PATH_RESPONSE_OFF_DEST_HASH
        li      a2, HASH_LEN
        call    .Ltprs_memeq
        bnez    a0, .Ltprs_found_cache

.Ltprs_next_slot:
        addi    s3, s3, TRANSPORT_PATH_RESPONSE_ENTRY_SIZE
        addi    s4, s4, -1
        j       .Ltprs_scan_slot

.Ltprs_found_cache:
        lw      s6, TRANSPORT_PATH_RESPONSE_OFF_RAW_LEN(s3)
        beqz    s6, .Ltprs_missing
        addi    a0, s3, TRANSPORT_PATH_RESPONSE_OFF_RAW
        mv      a1, s6
        mv      a2, zero
        call    lora_interface_send
        bnez    a0, .Ltprs_return

        li      a0, TRANSPORT_STATUS_FORWARDED
        j       .Ltprs_return

.Ltprs_invalid:
        li      a0, TRANSPORT_ERR_INVAL
        j       .Ltprs_return

.Ltprs_missing:
        li      a0, TRANSPORT_ERR_NOT_FOUND

.Ltprs_return:
        lw      s0, TPRS_S0_OFF(sp)
        lw      s1, TPRS_S1_OFF(sp)
        lw      s2, TPRS_S2_OFF(sp)
        lw      s3, TPRS_S3_OFF(sp)
        lw      s4, TPRS_S4_OFF(sp)
        lw      s5, TPRS_S5_OFF(sp)
        lw      s6, TPRS_S6_OFF(sp)
        lw      s7, TPRS_S7_OFF(sp)
        lw      ra, TPRS_RA_OFF(sp)
        addi    sp, sp, TPRS_FRAME
        ret

.Ltprs_memeq:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        lbu     t1, 0(a1)
        bne     t0, t1, 3f
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      li      a0, 1
        ret
3:      mv      a0, zero
        ret

        .size   transport_path_response_send, . - transport_path_response_send
