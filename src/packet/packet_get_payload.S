# ============================================================================
# @function:    packet_get_payload
# @module:      packet
# @inputs:      a0 = packet_t*, a1 = uint16_t* (out: length written here)
# @outputs:     a0 = pointer to payload (context byte + data) inside raw buffer
# @clobbers:    a0, t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~6)
# @ct:          not-required
# @spec:        upstream/Reticulum/RNS/Packet.py.unpack(); milestone-1 §packet
# @verify:      kat-only; trivial pointer arithmetic + 16-bit store
# @tests:       tests/packet/test_packet_get_payload.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* payload_ptr = raw_ptr + payload_off; *a1 = payload_len.
 * The "payload" includes the context byte (1 byte) followed by the
 * ciphertext / data; callers that want only the data slice past the
 * context byte themselves.
 */

        .include "packet.S"

        .section .text.packet_get_payload, "ax", @progbits
        .global packet_get_payload
        .type   packet_get_payload, @function
packet_get_payload:
        lw      t0, PKT_OFF_RAW_PTR(a0)
        lhu     t1, PKT_OFF_PAYLOAD_OFF(a0)
        add     t0, t0, t1
        lhu     t1, PKT_OFF_PAYLOAD_LEN(a0)
        sh      t1, 0(a1)
        mv      a0, t0
        ret
        .size   packet_get_payload, . - packet_get_payload
