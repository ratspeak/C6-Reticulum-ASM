# ============================================================================
# @function:    packet_get_dest_hash
# @module:      packet
# @inputs:      a0 = packet_t* (already populated by packet_parse_header)
# @outputs:     a0 = pointer to first of 16 destination-hash bytes (in raw buffer)
# @clobbers:    a0, t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~5)
# @ct:          not-required
# @spec:        upstream/Reticulum/RNS/Packet.py.unpack(); milestone-1 §packet
# @verify:      kat-only; trivial pointer arithmetic
# @tests:       tests/packet/test_packet_get_dest_hash.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* dest_hash_ptr = raw_ptr + dest_hash_off. Both fields are populated
 * by packet_parse_header; the caller must call that first.
 */

        .include "packet.S"

        .section .text.packet_get_dest_hash, "ax", @progbits
        .global packet_get_dest_hash
        .type   packet_get_dest_hash, @function
packet_get_dest_hash:
        lw      t0, PKT_OFF_RAW_PTR(a0)
        lhu     t1, PKT_OFF_DEST_HASH_OFF(a0)
        add     a0, t0, t1
        ret
        .size   packet_get_dest_hash, . - packet_get_dest_hash
