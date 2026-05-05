# ============================================================================
# @function:    announce_parse
# @module:      announce
# @inputs:      a0 = raw packet ptr, a1 = raw packet len, a2 = announce_rx_t* out
# @outputs:     a0 = 0 on success, -1 on malformed input; out populated on success
# @clobbers:    a0..a2, t0..t6, ra
# @preserves:   sp, gp, s0..s4
# @stack:       64
# @cycles:      bounded (~1400)
# @ct:          not-required
# @spec:        milestone-5 announce_parse
# @verify:      proofs/announce/announce_parse_bounds.py
# @tests:       tests/announce/test_announce_parse.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Parse a non-ratchet Reticulum HEADER_1 or HEADER_2 announce packet.
 *
 * The parser owns only fixed-field copies. App data is represented as a
 * pointer and length into the caller-owned raw packet buffer after the packet
 * length has been bounded to ANNOUNCE_RETICULUM_MDU.
 */

        .include "announce.S"
        .include "packet.S"

        .equ AP_PKT_OFF, 0
        .equ AP_S0_OFF,  24
        .equ AP_S1_OFF,  28
        .equ AP_S2_OFF,  32
        .equ AP_S3_OFF,  36
        .equ AP_S4_OFF,  40
        .equ AP_RA_OFF,  60
        .equ AP_FRAME,   64

        .section .text.announce_parse, "ax", @progbits
        .global announce_parse
        .type   announce_parse, @function
announce_parse:
        addi    sp, sp, -AP_FRAME
        sw      s0, AP_S0_OFF(sp)
        sw      s1, AP_S1_OFF(sp)
        sw      s2, AP_S2_OFF(sp)
        sw      s3, AP_S3_OFF(sp)
        sw      s4, AP_S4_OFF(sp)
        sw      ra, AP_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        mv      s2, a2                  /* announce_rx_t* out          */

        beqz    s0, .Lap_fail
        beqz    s2, .Lap_fail

        li      t0, ANNOUNCE_RETICULUM_MDU
        bltu    t0, s1, .Lap_fail       /* over local Reticulum MDU    */

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, AP_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Lap_fail

        lbu     t0, AP_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        beqz    t0, .Lap_h1_shape
        li      t1, ANNOUNCE_H2_BASE_RAW_LEN
        bltu    s1, t1, .Lap_fail       /* fixed H2 fields + signature */
        lbu     t0, ANNOUNCE_RAW_OFF_FLAGS(s0)
        li      t1, ANNOUNCE_HEADER2_FLAGS
        bne     t0, t1, .Lap_fail
        li      s3, ANNOUNCE_H2_BASE_RAW_LEN
        j       .Lap_shape_ready

.Lap_h1_shape:
        li      t1, ANNOUNCE_BASE_RAW_LEN
        bltu    s1, t1, .Lap_fail       /* fixed H1 fields + signature */
        lbu     t0, ANNOUNCE_RAW_OFF_FLAGS(s0)
        li      t1, ANNOUNCE_HEADER_FLAGS
        bne     t0, t1, .Lap_fail
        li      s3, ANNOUNCE_BASE_RAW_LEN

.Lap_shape_ready:
        lbu     t0, AP_PKT_OFF + PKT_OFF_PACKET_TYPE(sp)
        li      t1, PKT_ANNOUNCE
        bne     t0, t1, .Lap_fail

        lw      s4, AP_PKT_OFF + PKT_OFF_RAW_PTR(sp)
        lhu     t2, AP_PKT_OFF + PKT_OFF_PAYLOAD_OFF(sp)
        add     s4, s4, t2              /* context byte ptr            */
        lbu     t0, 0(s4)
        li      t1, ANNOUNCE_CONTEXT_NONE
        bne     t0, t1, .Lap_fail

        sw      s1, ANNOUNCE_RX_OFF_RAW_LEN(s2)
        lhu     t0, AP_PKT_OFF + PKT_OFF_PAYLOAD_OFF(sp)
        addi    t0, t0, 1              /* skip announce context byte  */
        sub     t1, s1, t0
        sw      t1, ANNOUNCE_RX_OFF_PAYLOAD_LEN(s2)
        sub     t1, s1, s3
        sw      t1, ANNOUNCE_RX_OFF_APP_DATA_LEN(s2)

        lhu     t0, AP_PKT_OFF + PKT_OFF_DEST_HASH_OFF(sp)
        add     a0, s0, t0
        addi    a1, s2, ANNOUNCE_RX_OFF_DEST_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Lap_copy_bytes

        addi    a0, s4, 1
        addi    a1, s2, ANNOUNCE_RX_OFF_PUBLIC_KEY
        li      a2, ANNOUNCE_PUBLIC_KEY_SIZE
        call    .Lap_copy_bytes

        addi    a0, s4, 65
        addi    a1, s2, ANNOUNCE_RX_OFF_NAME_HASH
        li      a2, ANNOUNCE_NAME_HASH_SIZE
        call    .Lap_copy_bytes

        addi    a0, s4, 75
        addi    a1, s2, ANNOUNCE_RX_OFF_RANDOM_HASH
        li      a2, ANNOUNCE_RANDOM_HASH_SIZE
        call    .Lap_copy_bytes

        addi    a0, s4, 85
        addi    a1, s2, ANNOUNCE_RX_OFF_SIGNATURE
        li      a2, ANNOUNCE_SIGNATURE_SIZE
        call    .Lap_copy_bytes

        addi    t0, s4, ANNOUNCE_PAYLOAD_FIXED_LEN
        sw      t0, ANNOUNCE_RX_OFF_APP_DATA_PTR(s2)

        li      a0, ANNOUNCE_OK
        j       .Lap_return

.Lap_fail:
        li      a0, ANNOUNCE_ERR_INVAL

.Lap_return:
        lw      s0, AP_S0_OFF(sp)
        lw      s1, AP_S1_OFF(sp)
        lw      s2, AP_S2_OFF(sp)
        lw      s3, AP_S3_OFF(sp)
        lw      s4, AP_S4_OFF(sp)
        lw      ra, AP_RA_OFF(sp)
        addi    sp, sp, AP_FRAME
        ret

.Lap_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   announce_parse, . - announce_parse
