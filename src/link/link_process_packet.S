# ============================================================================
# @function:    link_process_packet
# @module:      link
# @inputs:      a0 = raw packet ptr
#               a1 = raw packet len
#               a2 = interface_id
# @outputs:     a0 = stable status code for accepted, duplicate, decrypted, or invalid
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s8
# @stack:       160
# @cycles:      bounded (~4-entry link-table scan plus delegated processing)
# @ct:          not-required
# @spec:        milestone-6 link_process_packet
# @verify:      proofs/link/link_process_packet.py
# @tests:       tests/link/test_link_process_packet.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Dispatch inbound packets relevant to milestone 6:
 *
 *   LINKREQUEST  -> link_request_parse + link_handshake_accept
 *   ANNOUNCE     -> transport_process_announce (milestone-5 path preserved)
 *   DATA to LINK -> link table lookup by link_id + link_session_decrypt
 *
 * Decrypted plaintext is copied by link_session_decrypt into
 * link_session_scratch. Later milestones add resource/channel dispatch over
 * that plaintext; this milestone only proves one encrypted packet reaches the
 * authenticated session path.
 */

        .include "packet.S"
        .include "link.S"

        .equ LPP_PKT_OFF,  0       /* packet_t: 24 bytes             */
        .equ LPP_REQ_OFF,  24      /* link_request_t: 92 bytes       */
        .equ LPP_S0_OFF,   116
        .equ LPP_S1_OFF,   120
        .equ LPP_S2_OFF,   124
        .equ LPP_S3_OFF,   128
        .equ LPP_S4_OFF,   132
        .equ LPP_S5_OFF,   136
        .equ LPP_S6_OFF,   140
        .equ LPP_S7_OFF,   144
        .equ LPP_S8_OFF,   148
        .equ LPP_RA_OFF,   156
        .equ LPP_FRAME,    160

        .section .text.link_process_packet, "ax", @progbits
        .global link_process_packet
        .type   link_process_packet, @function
link_process_packet:
        addi    sp, sp, -LPP_FRAME
        sw      s0, LPP_S0_OFF(sp)
        sw      s1, LPP_S1_OFF(sp)
        sw      s2, LPP_S2_OFF(sp)
        sw      s3, LPP_S3_OFF(sp)
        sw      s4, LPP_S4_OFF(sp)
        sw      s5, LPP_S5_OFF(sp)
        sw      s6, LPP_S6_OFF(sp)
        sw      s7, LPP_S7_OFF(sp)
        sw      s8, LPP_S8_OFF(sp)
        sw      ra, LPP_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        mv      s2, a2                  /* interface_id                */
        beqz    s0, .Llpp_invalid

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, LPP_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Llpp_invalid

        lbu     t0, LPP_PKT_OFF + PKT_OFF_PACKET_TYPE(sp)
        li      t1, PKT_LINKREQUEST
        beq     t0, t1, .Llpp_link_request
        li      t1, PKT_ANNOUNCE
        beq     t0, t1, .Llpp_announce
        li      t1, PKT_DATA
        bne     t0, t1, .Llpp_invalid

        lbu     t0, LPP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Llpp_invalid
        lbu     t0, LPP_PKT_OFF + PKT_OFF_HEADER_BYTE(sp)
        andi    t0, t0, MASK_DEST_TYPE
        li      t1, LINK_DEST_TYPE_LINK_BITS
        bne     t0, t1, .Llpp_invalid

        lhu     s5, LPP_PKT_OFF + PKT_OFF_PAYLOAD_LEN(sp)
        li      t0, LINK_SESSION_TOKEN_OVERHEAD + 17
        bltu    s5, t0, .Llpp_invalid

        lw      t0, LPP_PKT_OFF + PKT_OFF_RAW_PTR(sp)
        lhu     t1, LPP_PKT_OFF + PKT_OFF_PAYLOAD_OFF(sp)
        add     s3, t0, t1              /* context byte ptr            */
        lbu     t2, 0(s3)
        li      t3, LINK_DATA_CONTEXT_NONE
        bne     t2, t3, .Llpp_invalid
        addi    s3, s3, 1               /* token ptr                   */
        addi    s5, s5, -1              /* token len                   */

        lhu     t1, LPP_PKT_OFF + PKT_OFF_DEST_HASH_OFF(sp)
        add     s4, t0, t1              /* packet destination/link id  */
        la      s7, link_table
        li      s8, LINK_TABLE_CAPACITY

.Llpp_scan:
        beqz    s8, .Llpp_invalid
        lbu     t0, LINK_ENTRY_OFF_VALID(s7)
        beqz    t0, .Llpp_next
        lbu     t0, LINK_ENTRY_OFF_STATUS(s7)
        li      t1, LINK_STATUS_ESTABLISHED
        bne     t0, t1, .Llpp_next
        addi    a0, s7, LINK_ENTRY_OFF_LINK_ID
        mv      a1, s4
        li      a2, LINK_ID_SIZE
        call    .Llpp_memeq
        bnez    a0, .Llpp_found

.Llpp_next:
        addi    s7, s7, LINK_ENTRY_SIZE
        addi    s8, s8, -1
        j       .Llpp_scan

.Llpp_found:
        mv      a0, s7
        mv      a1, s3
        mv      a2, s5
        la      a3, link_session_scratch
        li      a4, LINK_SESSION_PLAINTEXT_MAX
        call    link_session_decrypt
        blt     a0, zero, .Llpp_invalid
        li      a0, LINK_STATUS_DECRYPTED
        j       .Llpp_return

.Llpp_link_request:
        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, LPP_REQ_OFF
        call    link_request_parse
        bnez    a0, .Llpp_invalid
        addi    a0, sp, LPP_REQ_OFF
        call    link_handshake_accept
        blt     a0, zero, .Llpp_invalid
        j       .Llpp_return

.Llpp_announce:
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    transport_process_announce
        j       .Llpp_return

.Llpp_invalid:
        li      a0, LINK_ERR_INVAL

.Llpp_return:
        lw      s0, LPP_S0_OFF(sp)
        lw      s1, LPP_S1_OFF(sp)
        lw      s2, LPP_S2_OFF(sp)
        lw      s3, LPP_S3_OFF(sp)
        lw      s4, LPP_S4_OFF(sp)
        lw      s5, LPP_S5_OFF(sp)
        lw      s6, LPP_S6_OFF(sp)
        lw      s7, LPP_S7_OFF(sp)
        lw      s8, LPP_S8_OFF(sp)
        lw      ra, LPP_RA_OFF(sp)
        addi    sp, sp, LPP_FRAME
        ret

.Llpp_memeq:
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

        .size   link_process_packet, . - link_process_packet
