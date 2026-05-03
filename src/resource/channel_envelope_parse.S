# ============================================================================
# @function:    channel_envelope_parse
# @module:      resource
# @inputs:      a0 = raw envelope ptr
#               a1 = raw envelope len
#               a2 = channel_envelope_t* out
# @outputs:     a0 = 0 on success, negative errno on malformed input
# @clobbers:    a0..a7, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~40)
# @ct:          not-required
# @spec:        milestone-7 channel envelope; upstream RNS.Channel.Envelope.unpack()
# @verify:      proofs/resource/channel_envelope.py
# @tests:       tests/resource/test_channel_envelope.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Parse a Channel envelope prefix without copying payload bytes. */

        .include "resource.S"

        .section .text.channel_envelope_parse, "ax", @progbits
        .global channel_envelope_parse
        .type   channel_envelope_parse, @function
channel_envelope_parse:
        beqz    a0, .Lcep_invalid
        beqz    a2, .Lcep_invalid

        li      t0, CHANNEL_ENVELOPE_HEADER_LEN
        bltu    a1, t0, .Lcep_invalid
        li      t0, CHANNEL_ENVELOPE_MAX_RAW_LEN
        bltu    t0, a1, .Lcep_invalid

        lbu     t0, 0(a0)
        slli    t0, t0, 8
        lbu     t1, 1(a0)
        or      t0, t0, t1              /* msgtype                     */

        lbu     t2, 2(a0)
        slli    t2, t2, 8
        lbu     t3, 3(a0)
        or      t2, t2, t3              /* sequence                    */

        lbu     t4, 4(a0)
        slli    t4, t4, 8
        lbu     t5, 5(a0)
        or      t4, t4, t5              /* payload len                 */

        li      t5, CHANNEL_ENVELOPE_MAX_PAYLOAD
        bltu    t5, t4, .Lcep_invalid
        li      t5, CHANNEL_ENVELOPE_HEADER_LEN
        add     t6, t4, t5
        bne     t6, a1, .Lcep_invalid

        sw      a1, CHANNEL_ENV_OFF_RAW_LEN(a2)
        sw      t0, CHANNEL_ENV_OFF_MSGTYPE(a2)
        sw      t2, CHANNEL_ENV_OFF_SEQUENCE(a2)
        sw      t4, CHANNEL_ENV_OFF_PAYLOAD_LEN(a2)
        addi    t5, a0, CHANNEL_ENVELOPE_HEADER_LEN
        sw      t5, CHANNEL_ENV_OFF_PAYLOAD_PTR(a2)

        li      a0, RESOURCE_OK
        ret

.Lcep_invalid:
        li      a0, RESOURCE_ERR_INVAL
        ret

        .size   channel_envelope_parse, . - channel_envelope_parse
