# ============================================================================
# @function:    packet_parse_header
# @module:      packet
# @inputs:      a0 = raw ptr, a1 = raw len, a2 = packet_t* (caller-provided)
# @outputs:     a0 = 0 on success, -1 on truncated input
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~30)
# @ct:          not-required
# @spec:        upstream/Reticulum/RNS/Packet.py.unpack(); milestone-1 §packet
# @verify:      kat-only; differential test against tests/harness/oracle.packet_parse
# @tests:       tests/packet/test_packet_parse_header.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Reticulum wire-format header (per upstream Packet.py.unpack):
 *
 *   Byte 0  flags:
 *     bit 7    IFAC flag (ignored here)
 *     bit 6    header_type (0 = HEADER_1, 1 = HEADER_2)
 *     bit 5    context flag (ignored)
 *     bit 4    transport_type
 *     bits 2-3 destination_type
 *     bits 0-1 packet_type
 *   Byte 1  hops
 *   HEADER_1: bytes 2..17 = destination_hash (16)
 *   HEADER_2: bytes 2..17 = transport_id (16), bytes 18..33 = destination_hash (16)
 *   Then context byte + payload.
 *
 * Returns 0 + populated struct, or -1 if `raw_len` is shorter than the
 * required header. Does not validate signatures or context (deferred to
 * milestone 5+).
 */

        .include "packet.S"

        .section .text.packet_parse_header, "ax", @progbits
        .global packet_parse_header
        .type   packet_parse_header, @function
packet_parse_header:
        /* Minimum length check: HEADER_1 is 19 bytes (flags + hops + 16). */
        li      t0, HEADER_MINSIZE
        blt     a1, t0, .Lpph_truncated

        /* Read byte 0 (flags) and write fields into the struct. */
        lbu     t1, 0(a0)
        sb      t1, PKT_OFF_HEADER_BYTE(a2)

        andi    t2, t1, MASK_PACKET_TYPE
        sb      t2, PKT_OFF_PACKET_TYPE(a2)

        andi    t3, t1, FLAG_HEADER_TYPE
        srli    t3, t3, 6                       /* bit 6 → 0/1            */
        sb      t3, PKT_OFF_HEADER_TYPE(a2)

        /* Hops (byte 1). */
        lbu     t4, 1(a0)
        sb      t4, PKT_OFF_HOPS(a2)

        /* dest_hash_off / payload_off depend on header_type. */
        beqz    t3, .Lpph_h1
        /* HEADER_2: need 35 bytes minimum (2 + 16 + 16 + 1 ctx? — header
         * itself excluding ctx is 34; we require 35 so context exists). */
        li      t0, HEADER_H2_SIZE
        blt     a1, t0, .Lpph_truncated
        li      t5, 18                          /* dest_hash offset       */
        li      t6, 34                          /* payload (ctx+data) off */
        j       .Lpph_write_offsets

.Lpph_h1:
        li      t5, 2                           /* dest_hash offset       */
        li      t6, 18                          /* payload off (ctx+data) */

.Lpph_write_offsets:
        sh      t5, PKT_OFF_DEST_HASH_OFF(a2)
        sh      t6, PKT_OFF_PAYLOAD_OFF(a2)

        /* payload_len = raw_len - payload_off (bounded; raw_len ≥ off
         * since the truncation check above asserted payload_off+1 ≤ len
         * for HEADER_1 and == HEADER_H2_SIZE − 1 for HEADER_2). */
        sub     t0, a1, t6
        sh      t0, PKT_OFF_PAYLOAD_LEN(a2)

        sh      a1, PKT_OFF_RAW_LEN(a2)
        sw      a0, PKT_OFF_RAW_PTR(a2)

        li      a0, PKT_OK
        ret

.Lpph_truncated:
        li      a0, PKT_ERR_TRUNCATED
        ret

        .size   packet_parse_header, . - packet_parse_header
