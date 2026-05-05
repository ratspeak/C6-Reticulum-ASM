# ============================================================================
# @function:    transport_process_packet
# @module:      transport
# @inputs:      a0 = raw packet ptr, a1 = raw packet len, a2 = interface_id
# @outputs:     a0 = transport/link dispatch status; TRANSPORT_ERR_INVAL on malformed input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s2
# @stack:       48
# @cycles:      bounded (~2 delegated dispatcher calls)
# @ct:          not-required
# @spec:        minimal LoRa transport-node ingress dispatcher
# @verify:      proofs/transport/transport_process_packet.py
# @tests:       tests/transport/test_transport_process_packet.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

/* Own the Reticulum transport ingress boundary for interface RX paths.
 *
 * ANNOUNCE packets are handled directly by the transport path-learning
 * pipeline. Non-announce packets still delegate to link_process_packet for
 * the existing local/link behavior; transit forwarding is added in a later
 * transport slice once packet-hash dedupe and HEADER_2 next-hop handling are
 * present.
 */

        .include "packet.S"
        .include "transport.S"

        .equ TPP_PKT_OFF, 0
        .equ TPP_S0_OFF,  24
        .equ TPP_S1_OFF,  28
        .equ TPP_S2_OFF,  32
        .equ TPP_RA_OFF,  44
        .equ TPP_FRAME,   48

        .section .text.transport_process_packet, "ax", @progbits
        .global transport_process_packet
        .type   transport_process_packet, @function
transport_process_packet:
        addi    sp, sp, -TPP_FRAME
        sw      s0, TPP_S0_OFF(sp)
        sw      s1, TPP_S1_OFF(sp)
        sw      s2, TPP_S2_OFF(sp)
        sw      ra, TPP_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        mv      s2, a2                  /* interface_id                */
        beqz    s0, .Ltpp_invalid

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, TPP_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Ltpp_invalid

        lbu     t0, TPP_PKT_OFF + PKT_OFF_PACKET_TYPE(sp)
        li      t1, PKT_ANNOUNCE
        beq     t0, t1, .Ltpp_announce

        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    link_process_packet
        j       .Ltpp_return

.Ltpp_announce:
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    transport_process_announce
        j       .Ltpp_return

.Ltpp_invalid:
        li      a0, TRANSPORT_ERR_INVAL

.Ltpp_return:
        lw      s0, TPP_S0_OFF(sp)
        lw      s1, TPP_S1_OFF(sp)
        lw      s2, TPP_S2_OFF(sp)
        lw      ra, TPP_RA_OFF(sp)
        addi    sp, sp, TPP_FRAME
        ret

        .size   transport_process_packet, . - transport_process_packet
