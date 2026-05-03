# ============================================================================
# @function:    channel_envelope_build
# @module:      resource
# @inputs:      a0 = msgtype (uint16)
#               a1 = sequence (uint16)
#               a2 = payload ptr
#               a3 = payload len
#               a4 = raw envelope out ptr
#               a5 = raw envelope capacity
# @outputs:     a0 = raw envelope length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s6
# @stack:       48
# @cycles:      bounded (<= 425-byte payload copy)
# @ct:          not-required
# @spec:        milestone-7 channel envelope; upstream RNS.Channel.Envelope.pack()
# @verify:      proofs/resource/channel_envelope.py
# @tests:       tests/resource/test_channel_envelope.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Build the upstream Channel envelope prefix:
 *
 *   msgtype[2] || sequence[2] || payload_len[2] || payload[payload_len]
 *
 * All integer fields are big-endian uint16.
 */

        .include "resource.S"

        .equ CEB_S0_OFF, 0
        .equ CEB_S1_OFF, 4
        .equ CEB_S2_OFF, 8
        .equ CEB_S3_OFF, 12
        .equ CEB_S4_OFF, 16
        .equ CEB_S5_OFF, 20
        .equ CEB_S6_OFF, 24
        .equ CEB_RA_OFF, 44
        .equ CEB_FRAME,  48

        .section .text.channel_envelope_build, "ax", @progbits
        .global channel_envelope_build
        .type   channel_envelope_build, @function
channel_envelope_build:
        addi    sp, sp, -CEB_FRAME
        sw      s0, CEB_S0_OFF(sp)
        sw      s1, CEB_S1_OFF(sp)
        sw      s2, CEB_S2_OFF(sp)
        sw      s3, CEB_S3_OFF(sp)
        sw      s4, CEB_S4_OFF(sp)
        sw      s5, CEB_S5_OFF(sp)
        sw      s6, CEB_S6_OFF(sp)
        sw      ra, CEB_RA_OFF(sp)

        mv      s0, a0                  /* msgtype                     */
        mv      s1, a1                  /* sequence                    */
        mv      s2, a2                  /* payload ptr                 */
        mv      s3, a3                  /* payload len                 */
        mv      s4, a4                  /* out ptr                     */
        mv      s5, a5                  /* out capacity                */

        beqz    s4, .Lceb_invalid
        bnez    s2, .Lceb_have_payload
        bnez    s3, .Lceb_invalid
.Lceb_have_payload:
        li      t0, 0xFFFF
        bltu    t0, s0, .Lceb_invalid
        bltu    t0, s1, .Lceb_invalid
        li      t0, CHANNEL_ENVELOPE_MAX_PAYLOAD
        bltu    t0, s3, .Lceb_overflow

        li      t0, CHANNEL_ENVELOPE_HEADER_LEN
        add     s6, s3, t0
        bltu    s5, s6, .Lceb_overflow

        srli    t0, s0, 8
        sb      t0, 0(s4)
        sb      s0, 1(s4)
        srli    t0, s1, 8
        sb      t0, 2(s4)
        sb      s1, 3(s4)
        srli    t0, s3, 8
        sb      t0, 4(s4)
        sb      s3, 5(s4)

        mv      a0, s2
        addi    a1, s4, CHANNEL_ENVELOPE_HEADER_LEN
        mv      a2, s3
        call    .Lceb_copy_bytes

        mv      a0, s6
        j       .Lceb_return

.Lceb_invalid:
        li      a0, RESOURCE_ERR_INVAL
        j       .Lceb_return

.Lceb_overflow:
        li      a0, RESOURCE_ERR_OVERFLOW

.Lceb_return:
        lw      s0, CEB_S0_OFF(sp)
        lw      s1, CEB_S1_OFF(sp)
        lw      s2, CEB_S2_OFF(sp)
        lw      s3, CEB_S3_OFF(sp)
        lw      s4, CEB_S4_OFF(sp)
        lw      s5, CEB_S5_OFF(sp)
        lw      s6, CEB_S6_OFF(sp)
        lw      ra, CEB_RA_OFF(sp)
        addi    sp, sp, CEB_FRAME
        ret

.Lceb_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   channel_envelope_build, . - channel_envelope_build
