# ============================================================================
# @function:    packet_serialize_header
# @module:      packet
# @inputs:      a0 = packet_t* (source), a1 = dst ptr, a2 = dst capacity
# @outputs:     a0 = bytes written, OR -1 on overflow
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~30 + payload bytes copied)
# @ct:          not-required
# @spec:        upstream/Reticulum/RNS/Packet.py.pack(); milestone-1 §packet
# @verify:      kat-only; skeleton — full announce serialiser lands in milestone 3
# @tests:       tests/packet/test_packet_serialize_header.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Inverse of packet_parse_header for a packet whose struct is already
 * populated. Today this is the round-trip path used by tests: emit
 * exactly the bytes packet_parse_header just consumed, with the
 * payload copied verbatim from raw_ptr.
 *
 * Milestone 3 (announce TX) replaces this with the construction path
 * that builds the header from identity + destination + flags rather
 * than copying. The struct layout and this function's signature are
 * pinned now; only the body grows.
 */

        .include "packet.S"

        .section .text.packet_serialize_header, "ax", @progbits
        .global packet_serialize_header
        .type   packet_serialize_header, @function
packet_serialize_header:
        /* total = raw_len. If dst capacity < total → overflow. */
        lhu     t0, PKT_OFF_RAW_LEN(a0)
        blt     a2, t0, .Lpsh_overflow

        /* Bytewise copy raw_ptr[0..raw_len) → dst. */
        lw      t1, PKT_OFF_RAW_PTR(a0)         /* src                    */
        mv      t2, a1                          /* dst cursor            */
        add     t3, a1, t0                      /* dst end               */
1:      beq     t2, t3, .Lpsh_done
        lbu     t4, 0(t1)
        sb      t4, 0(t2)
        addi    t1, t1, 1
        addi    t2, t2, 1
        j       1b

.Lpsh_done:
        mv      a0, t0
        ret

.Lpsh_overflow:
        li      a0, -1
        ret

        .size   packet_serialize_header, . - packet_serialize_header
