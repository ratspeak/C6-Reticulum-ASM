# ============================================================================
# @function:    transport_process_packet
# @module:      transport
# @inputs:      a0 = raw packet ptr, a1 = raw packet len, a2 = interface_id
# @outputs:     a0 = transport/link dispatch status; TRANSPORT_ERR_INVAL on malformed input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s6
# @stack:       176
# @cycles:      bounded (~1 packet hash check plus path lookup/forward or delegated dispatch)
# @ct:          not-required
# @spec:        minimal LoRa transport-node ingress dispatcher
# @verify:      proofs/transport/transport_process_packet.py
# @tests:       tests/transport/test_transport_process_packet.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

/* Own the Reticulum transport ingress boundary for interface RX paths.
 *
 * transport_packet_seen suppresses duplicate packets before dispatch.
 * ANNOUNCE packets are handled directly by the transport path-learning
 * pipeline. HEADER_2 packets addressed to this node can be stripped and
 * forwarded to known one-hop LoRa destinations. Other non-announce packets
 * still delegate to link_process_packet for the existing local/link behavior.
 */

        .include "announce.S"
        .include "identity.S"
        .include "lora.S"
        .include "packet.S"
        .include "transport.S"

        .equ TPP_PKT_OFF,   0
        .equ TPP_ENTRY_OFF, 24
        .equ TPP_S0_OFF,    144
        .equ TPP_S1_OFF,    148
        .equ TPP_S2_OFF,    152
        .equ TPP_S3_OFF,    156
        .equ TPP_S4_OFF,    160
        .equ TPP_S5_OFF,    164
        .equ TPP_S6_OFF,    168
        .equ TPP_RA_OFF,    172
        .equ TPP_FRAME,     176

        .section .rodata.transport_process_packet, "a", @progbits
.Ltpp_path_request_dest_hash:
        .byte   0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa
        .byte   0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61

        .section .text.transport_process_packet, "ax", @progbits
        .global transport_process_packet
        .type   transport_process_packet, @function
transport_process_packet:
        addi    sp, sp, -TPP_FRAME
        sw      s0, TPP_S0_OFF(sp)
        sw      s1, TPP_S1_OFF(sp)
        sw      s2, TPP_S2_OFF(sp)
        sw      s3, TPP_S3_OFF(sp)
        sw      s4, TPP_S4_OFF(sp)
        sw      s5, TPP_S5_OFF(sp)
        sw      s6, TPP_S6_OFF(sp)
        sw      ra, TPP_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        mv      s2, a2                  /* interface_id                */
        beqz    s0, .Ltpp_invalid

        mv      a0, s0
        mv      a1, s1
        call    transport_packet_seen
        blt     a0, zero, .Ltpp_invalid
        li      t0, TRANSPORT_STATUS_DUPLICATE
        beq     a0, t0, .Ltpp_return

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, TPP_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Ltpp_invalid

        lbu     t0, TPP_PKT_OFF + PKT_OFF_PACKET_TYPE(sp)
        li      t1, PKT_ANNOUNCE
        beq     t0, t1, .Ltpp_announce
        li      t1, PKT_DATA
        beq     t0, t1, .Ltpp_data

        lbu     t0, TPP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Ltpp_transport

        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    link_process_packet
        j       .Ltpp_return

.Ltpp_data:
        lbu     t0, TPP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Ltpp_transport

        lhu     t0, TPP_PKT_OFF + PKT_OFF_PAYLOAD_OFF(sp)
        add     s3, s0, t0              /* context byte ptr             */
        lhu     s4, TPP_PKT_OFF + PKT_OFF_PAYLOAD_LEN(sp)
        beqz    s4, .Ltpp_link_dispatch

        lbu     t1, 0(s3)
        li      t2, TRANSPORT_CONTEXT_NONE
        bne     t1, t2, .Ltpp_link_dispatch

        lhu     t0, TPP_PKT_OFF + PKT_OFF_DEST_HASH_OFF(sp)
        add     a0, s0, t0
        la      a1, .Ltpp_path_request_dest_hash
        li      a2, HASH_LEN
        call    .Ltpp_memeq
        beqz    a0, .Ltpp_link_dispatch

        addi    s3, s3, 1               /* path-request data ptr        */
        addi    s4, s4, -1              /* path-request data len        */
        li      t0, HASH_LEN * 2
        bltu    s4, t0, .Ltpp_not_found /* requested hash + tag         */

        mv      a0, s3                  /* requested destination hash   */
        mv      a1, zero
        bltu    t0, s4, .Ltpp_path_request_with_requestor
        j       .Ltpp_path_request_ready

.Ltpp_path_request_with_requestor:
        addi    a1, s3, HASH_LEN        /* requestor transport id       */

.Ltpp_path_request_ready:
        mv      a2, s2
        call    transport_path_response_send
        j       .Ltpp_return

.Ltpp_link_dispatch:
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    link_process_packet
        j       .Ltpp_return

.Ltpp_transport:
        addi    a0, s0, 2              /* HEADER_2 transport_id       */
        la      a1, identity_current
        addi    a1, a1, IDENTITY_OFF_HASH
        li      a2, HASH_LEN
        call    .Ltpp_memeq
        beqz    a0, .Ltpp_not_found

        lhu     t0, TPP_PKT_OFF + PKT_OFF_DEST_HASH_OFF(sp)
        add     a0, s0, t0
        addi    a1, sp, TPP_ENTRY_OFF
        call    transport_path_lookup
        bnez    a0, .Ltpp_not_found

        lbu     t0, TPP_ENTRY_OFF + TRANSPORT_PATH_OFF_INTERFACE(sp)
        li      t1, TRANSPORT_INTERFACE_LORA
        bne     t0, t1, .Ltpp_not_found

        lbu     t0, TPP_ENTRY_OFF + TRANSPORT_PATH_OFF_HOPS(sp)
        li      t1, 1
        beq     t0, t1, .Ltpp_strip_to_h1
        bltu    t1, t0, .Ltpp_forward_h2
        j       .Ltpp_not_found

.Ltpp_forward_h2:
        addi    s3, sp, TPP_ENTRY_OFF + TRANSPORT_PATH_OFF_NEXT_HOP
        addi    s4, s0, 2
        li      s5, HASH_LEN
.Ltpp_next_hop_copy:
        beqz    s5, .Ltpp_h2_send
        lbu     t0, 0(s3)
        sb      t0, 0(s4)
        addi    s3, s3, 1
        addi    s4, s4, 1
        addi    s5, s5, -1
        j       .Ltpp_next_hop_copy

.Ltpp_h2_send:
        lbu     t1, 1(s0)
        addi    t1, t1, 1
        sb      t1, 1(s0)
        mv      a0, s0
        mv      a1, s1
        mv      a2, zero
        call    lora_interface_send
        bnez    a0, .Ltpp_return
        li      a0, TRANSPORT_STATUS_FORWARDED
        j       .Ltpp_return

.Ltpp_strip_to_h1:
        lbu     t0, 0(s0)
        andi    t0, t0, 0x0f
        sb      t0, 0(s0)
        lbu     t1, 1(s0)
        addi    t1, t1, 1
        sb      t1, 1(s0)

        addi    s3, s0, HASH_LEN + 2    /* src = old dest hash         */
        addi    s4, s0, 2               /* dst = HEADER_1 dest hash    */
        addi    s5, s1, -(HASH_LEN + 2) /* bytes from dest through end  */
        mv      s6, s5
.Ltpp_strip_copy:
        beqz    s6, .Ltpp_send_forward
        lbu     t0, 0(s3)
        sb      t0, 0(s4)
        addi    s3, s3, 1
        addi    s4, s4, 1
        addi    s6, s6, -1
        j       .Ltpp_strip_copy

.Ltpp_send_forward:
        mv      a0, s0
        addi    a1, s1, -HASH_LEN
        mv      a2, zero
        call    lora_interface_send
        bnez    a0, .Ltpp_return
        li      a0, TRANSPORT_STATUS_FORWARDED
        j       .Ltpp_return

.Ltpp_announce:
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    transport_process_announce
        mv      s3, a0
        beqz    a0, .Ltpp_rebroadcast_announce
        li      t0, TRANSPORT_STATUS_UPDATED
        bne     a0, t0, .Ltpp_return

.Ltpp_rebroadcast_announce:
        li      t0, TRANSPORT_INTERFACE_LORA
        bne     s2, t0, .Ltpp_announce_status

        lbu     t0, TPP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Ltpp_announce_h2_rebroadcast

        li      t0, SX1262_BENCH_PAYLOAD_MAX - HASH_LEN
        bltu    t0, s1, .Ltpp_announce_status

        add     s4, s0, s1
        addi    s4, s4, -1             /* src = old final byte        */
        addi    s5, s4, HASH_LEN        /* dst = new final byte        */
        addi    s6, s1, -2              /* move old dest+payload       */
.Ltpp_announce_shift:
        beqz    s6, .Ltpp_announce_transport_id
        lbu     t0, 0(s4)
        sb      t0, 0(s5)
        addi    s4, s4, -1
        addi    s5, s5, -1
        addi    s6, s6, -1
        j       .Ltpp_announce_shift

.Ltpp_announce_transport_id:
        la      s4, identity_current
        addi    s4, s4, IDENTITY_OFF_HASH
        addi    s5, s0, 2
        li      s6, HASH_LEN
.Ltpp_announce_tid_copy:
        beqz    s6, .Ltpp_announce_header
        lbu     t0, 0(s4)
        sb      t0, 0(s5)
        addi    s4, s4, 1
        addi    s5, s5, 1
        addi    s6, s6, -1
        j       .Ltpp_announce_tid_copy

.Ltpp_announce_header:
        lbu     t0, 0(s0)
        andi    t0, t0, 0x0f
        ori     t0, t0, FLAG_HEADER_TYPE | FLAG_TRANSPORT
        sb      t0, 0(s0)
        lbu     t1, 1(s0)
        addi    t1, t1, 1
        sb      t1, 1(s0)

        mv      a0, s0
        addi    a1, s1, HASH_LEN
        mv      a2, zero
        call    lora_interface_send
        bnez    a0, .Ltpp_return
        j       .Ltpp_announce_status

.Ltpp_announce_h2_rebroadcast:
        li      t0, SX1262_BENCH_PAYLOAD_MAX
        bltu    t0, s1, .Ltpp_announce_status
        la      s4, identity_current
        addi    s4, s4, IDENTITY_OFF_HASH
        addi    s5, s0, ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID
        li      s6, HASH_LEN
.Ltpp_announce_h2_tid_copy:
        beqz    s6, .Ltpp_announce_h2_header
        lbu     t0, 0(s4)
        sb      t0, 0(s5)
        addi    s4, s4, 1
        addi    s5, s5, 1
        addi    s6, s6, -1
        j       .Ltpp_announce_h2_tid_copy

.Ltpp_announce_h2_header:
        lbu     t0, 0(s0)
        andi    t0, t0, 0x0f
        ori     t0, t0, FLAG_HEADER_TYPE | FLAG_TRANSPORT
        sb      t0, 0(s0)
        lbu     t1, 1(s0)
        addi    t1, t1, 1
        sb      t1, 1(s0)
        mv      a0, s0
        mv      a1, s1
        mv      a2, zero
        call    lora_interface_send
        bnez    a0, .Ltpp_return

.Ltpp_announce_status:
        mv      a0, s3
        j       .Ltpp_return

.Ltpp_invalid:
        li      a0, TRANSPORT_ERR_INVAL
        j       .Ltpp_return

.Ltpp_not_found:
        li      a0, TRANSPORT_ERR_NOT_FOUND

.Ltpp_return:
        lw      s0, TPP_S0_OFF(sp)
        lw      s1, TPP_S1_OFF(sp)
        lw      s2, TPP_S2_OFF(sp)
        lw      s3, TPP_S3_OFF(sp)
        lw      s4, TPP_S4_OFF(sp)
        lw      s5, TPP_S5_OFF(sp)
        lw      s6, TPP_S6_OFF(sp)
        lw      ra, TPP_RA_OFF(sp)
        addi    sp, sp, TPP_FRAME
        ret

.Ltpp_memeq:
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

        .size   transport_process_packet, . - transport_process_packet
