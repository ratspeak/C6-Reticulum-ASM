# ============================================================================
# @function:    link_request_parse
# @module:      link
# @inputs:      a0 = raw packet ptr, a1 = raw packet len, a2 = link_request_t* out
# @outputs:     a0 = 0 on success, -1 on malformed or unsupported input
# @clobbers:    a0..a2, t0..t6, ra
# @preserves:   sp, gp, s0..s2
# @stack:       48
# @cycles:      bounded (~700)
# @ct:          not-required
# @spec:        milestone-6 link_request_parse; upstream RNS.Link current request payload subset
# @verify:      proofs/link/link_request.py
# @tests:       tests/link/test_link_request.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Parse the milestone-6 Reticulum link request subset.
 *
 * Accepted packets must be current HEADER_1 LINKREQUEST packets with context
 * NONE and the default signalling bytes for MTU 500 / AES-256-CBC. Legacy
 * 64-byte requests without signalling and alternate modes are intentionally
 * rejected for this first link-establishment slice.
 */

        .include "link.S"
        .include "packet.S"

        .equ LRP_PKT_OFF, 0
        .equ LRP_S0_OFF,  24
        .equ LRP_S1_OFF,  28
        .equ LRP_S2_OFF,  32
        .equ LRP_RA_OFF,  44
        .equ LRP_FRAME,   48

        .section .text.link_request_parse, "ax", @progbits
        .global link_request_parse
        .type   link_request_parse, @function
link_request_parse:
        addi    sp, sp, -LRP_FRAME
        sw      s0, LRP_S0_OFF(sp)
        sw      s1, LRP_S1_OFF(sp)
        sw      s2, LRP_S2_OFF(sp)
        sw      ra, LRP_RA_OFF(sp)

        mv      s0, a0
        mv      s1, a1
        mv      s2, a2

        beqz    s0, .Llrp_fail
        beqz    s2, .Llrp_fail

        li      t0, LINK_REQUEST_RAW_LEN
        bltu    s1, t0, .Llrp_fail
        li      t0, LINK_REQUEST_RETICULUM_MDU
        bltu    t0, s1, .Llrp_fail
        li      t0, LINK_REQUEST_RAW_LEN
        bne     s1, t0, .Llrp_fail

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, LRP_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Llrp_fail

        lbu     t0, LRP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Llrp_fail
        lbu     t0, LRP_PKT_OFF + PKT_OFF_PACKET_TYPE(sp)
        li      t1, PKT_LINKREQUEST
        bne     t0, t1, .Llrp_fail

        lbu     t0, LINK_REQUEST_RAW_OFF_FLAGS(s0)
        li      t1, LINK_REQUEST_HEADER_FLAGS
        bne     t0, t1, .Llrp_fail
        lbu     t0, LINK_REQUEST_RAW_OFF_CONTEXT(s0)
        li      t1, LINK_REQUEST_CONTEXT_NONE
        bne     t0, t1, .Llrp_fail

        lbu     t0, LINK_REQUEST_RAW_OFF_SIGNAL0(s0)
        li      t1, LINK_SIGNAL_BYTE0
        bne     t0, t1, .Llrp_fail
        lbu     t0, LINK_REQUEST_RAW_OFF_SIGNAL1(s0)
        li      t1, LINK_SIGNAL_BYTE1
        bne     t0, t1, .Llrp_fail
        lbu     t0, LINK_REQUEST_RAW_OFF_SIGNAL2(s0)
        li      t1, LINK_SIGNAL_BYTE2
        bne     t0, t1, .Llrp_fail

        sw      s1, LINK_REQUEST_OFF_RAW_LEN(s2)
        li      t0, LINK_DEFAULT_MTU
        sw      t0, LINK_REQUEST_OFF_MTU(s2)
        li      t0, LINK_MODE_AES256_CBC
        sw      t0, LINK_REQUEST_OFF_MODE(s2)

        addi    a0, s0, LINK_REQUEST_RAW_OFF_DEST_HASH
        addi    a1, s2, LINK_REQUEST_OFF_DEST_HASH
        li      a2, LINK_DESTINATION_HASH_SIZE
        call    .Llrp_copy_bytes

        addi    a0, s0, LINK_REQUEST_RAW_OFF_X25519_PUB
        addi    a1, s2, LINK_REQUEST_OFF_X25519_PUB
        li      a2, LINK_X25519_PUB_SIZE
        call    .Llrp_copy_bytes

        addi    a0, s0, LINK_REQUEST_RAW_OFF_ED25519_PUB
        addi    a1, s2, LINK_REQUEST_OFF_ED25519_PUB
        li      a2, LINK_ED25519_PUB_SIZE
        call    .Llrp_copy_bytes

        li      a0, LINK_OK
        j       .Llrp_return

.Llrp_fail:
        li      a0, LINK_ERR_INVAL

.Llrp_return:
        lw      s0, LRP_S0_OFF(sp)
        lw      s1, LRP_S1_OFF(sp)
        lw      s2, LRP_S2_OFF(sp)
        lw      ra, LRP_RA_OFF(sp)
        addi    sp, sp, LRP_FRAME
        ret

.Llrp_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   link_request_parse, . - link_request_parse
