# ============================================================================
# @function:    lxmf_payload_parse
# @module:      lxmf
# @inputs:      a0 = payload ptr, a1 = payload len, a2 = lxmf_payload_parsed_t* out
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       64
# @cycles:      bounded (<= 431-byte stamped payload scan)
# @ct:          not-required
# @spec:        milestone-9 payload codec; upstream LXMF/LXMessage.py unpack payload subset
# @verify:      proofs/lxmf/lxmf_payload_parse.py
# @tests:       tests/lxmf/test_lxmf_payload_parse.py
# @adrs:        0001, 0002, 0005, 0006, 0007
# @status:      verified
# ============================================================================

/* Parse the milestone-9 LXMF payload subset:
 *
 *   msgpack([timestamp_f64, title_bin, content_bin, fields_map])
 *   msgpack([timestamp_f64, title_bin, content_bin, fields_map, stamp_bin])
 *
 * Fields are preserved as a raw msgpack map view after bounded shallow scalar
 * validation. Nested field maps/arrays are rejected in this milestone. If a
 * fifth stamp is present, the parser copies the first four elements into the
 * output struct's no-stamp buffer with a fixarray4 header so later message-id
 * and signature functions hash the same bytes upstream Python repacks.
 */

        .include "lxmf.S"

        .equ LPP_S0_OFF,   0
        .equ LPP_S1_OFF,   4
        .equ LPP_S2_OFF,   8
        .equ LPP_S3_OFF,   12
        .equ LPP_S4_OFF,   16
        .equ LPP_S5_OFF,   20
        .equ LPP_S6_OFF,   24
        .equ LPP_S7_OFF,   28
        .equ LPP_S8_OFF,   32
        .equ LPP_S9_OFF,   36
        .equ LPP_S10_OFF,  40
        .equ LPP_S11_OFF,  44
        .equ LPP_RA_OFF,   60
        .equ LPP_FRAME,    64

        .section .text.lxmf_payload_parse, "ax", @progbits
        .global lxmf_payload_parse
        .type   lxmf_payload_parse, @function
lxmf_payload_parse:
        addi    sp, sp, -LPP_FRAME
        sw      s0, LPP_S0_OFF(sp)
        sw      s1, LPP_S1_OFF(sp)
        sw      s2, LPP_S2_OFF(sp)
        sw      s3, LPP_S3_OFF(sp)
        sw      s4, LPP_S4_OFF(sp)
        sw      s5, LPP_S5_OFF(sp)
        sw      s6, LPP_S6_OFF(sp)
        sw      s7, LPP_S7_OFF(sp)
        sw      s8, LPP_S8_OFF(sp)
        sw      s9, LPP_S9_OFF(sp)
        sw      s10, LPP_S10_OFF(sp)
        sw      s11, LPP_S11_OFF(sp)
        sw      ra, LPP_RA_OFF(sp)

        mv      s0, a0                  /* raw payload ptr              */
        mv      s1, a1                  /* raw payload len              */
        mv      s2, a2                  /* parsed output                */

        beqz    s0, .Llpp_invalid
        beqz    s2, .Llpp_invalid
        li      t0, LXMF_PAYLOAD_MAX_STAMPED_LEN
        bltu    t0, s1, .Llpp_overflow

        mv      s3, s0                  /* cursor                       */
        add     s4, s0, s1              /* end                          */
        li      s5, 0                   /* has stamp                    */
        li      s9, 0                   /* stamp ptr                    */
        li      s10, 0                  /* stamp len                    */

        call    .Llpp_read_byte
        bltz    a0, .Llpp_invalid
        li      t0, LXMF_MSGPACK_FIXARRAY4
        beq     a0, t0, .Llpp_array_ok
        li      t0, LXMF_MSGPACK_FIXARRAY5
        bne     a0, t0, .Llpp_invalid
        li      s5, LXMF_PAYLOAD_PARSED_HAS_STAMP
.Llpp_array_ok:

        call    .Llpp_read_byte
        bltz    a0, .Llpp_invalid
        li      t0, LXMF_MSGPACK_FLOAT64
        bne     a0, t0, .Llpp_invalid
        sub     t0, s4, s3
        li      t1, LXMF_TIMESTAMP_SIZE
        bltu    t0, t1, .Llpp_invalid
        sw      s3, LXMF_PAYLOAD_PARSED_OFF_TIMESTAMP_BE_PTR(s2)
        addi    s3, s3, LXMF_TIMESTAMP_SIZE

        call    .Llpp_parse_bin8
        beqz    a0, .Llpp_invalid
        li      t0, LXMF_PAYLOAD_MAX_TITLE
        bltu    t0, a1, .Llpp_overflow
        sw      a0, LXMF_PAYLOAD_PARSED_OFF_TITLE_PTR(s2)
        sw      a1, LXMF_PAYLOAD_PARSED_OFF_TITLE_LEN(s2)

        call    .Llpp_parse_bin8
        beqz    a0, .Llpp_invalid
        li      t0, LXMF_PAYLOAD_MAX_CONTENT
        bltu    t0, a1, .Llpp_overflow
        sw      a0, LXMF_PAYLOAD_PARSED_OFF_CONTENT_PTR(s2)
        sw      a1, LXMF_PAYLOAD_PARSED_OFF_CONTENT_LEN(s2)

        mv      s6, s3                  /* fields start                 */
        call    .Llpp_parse_fields_map
        bltz    a0, .Llpp_parse_error
        sub     s7, s3, s6              /* fields len                   */
        li      t0, LXMF_PAYLOAD_MAX_FIELDS
        bltu    t0, s7, .Llpp_overflow
        sw      s6, LXMF_PAYLOAD_PARSED_OFF_FIELDS_PTR(s2)
        sw      s7, LXMF_PAYLOAD_PARSED_OFF_FIELDS_LEN(s2)

        sub     s8, s3, s0              /* no-stamp payload len         */
        li      t0, LXMF_PAYLOAD_MAX_LEN
        bltu    t0, s8, .Llpp_overflow

        beqz    s5, .Llpp_no_stamp
        call    .Llpp_parse_bin8
        beqz    a0, .Llpp_invalid
        mv      s9, a0
        mv      s10, a1
        beqz    s10, .Llpp_invalid
        li      t0, LXMF_STAMP_MAX_LEN
        bltu    t0, s10, .Llpp_overflow
        bne     s3, s4, .Llpp_invalid

        addi    a1, s2, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_BUF
        sw      a1, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR(s2)
        sw      s8, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN(s2)
        li      t0, LXMF_MSGPACK_FIXARRAY4
        sb      t0, 0(a1)
        addi    a0, s0, 1
        addi    a1, a1, 1
        addi    a2, s8, -1
        call    .Llpp_copy_bytes
        j       .Llpp_success

.Llpp_no_stamp:
        bne     s3, s4, .Llpp_invalid
        sw      s0, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR(s2)
        sw      s1, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN(s2)

.Llpp_success:
        sw      s0, LXMF_PAYLOAD_PARSED_OFF_RAW_PTR(s2)
        sw      s1, LXMF_PAYLOAD_PARSED_OFF_RAW_LEN(s2)
        sw      s9, LXMF_PAYLOAD_PARSED_OFF_STAMP_PTR(s2)
        sw      s10, LXMF_PAYLOAD_PARSED_OFF_STAMP_LEN(s2)
        sw      s5, LXMF_PAYLOAD_PARSED_OFF_FLAGS(s2)
        li      a0, LXMF_OK
        j       .Llpp_done

.Llpp_parse_error:
        li      t0, LXMF_ERR_OVERFLOW
        beq     a0, t0, .Llpp_overflow
        j       .Llpp_invalid

.Llpp_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llpp_done

.Llpp_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Llpp_done:
        lw      s0, LPP_S0_OFF(sp)
        lw      s1, LPP_S1_OFF(sp)
        lw      s2, LPP_S2_OFF(sp)
        lw      s3, LPP_S3_OFF(sp)
        lw      s4, LPP_S4_OFF(sp)
        lw      s5, LPP_S5_OFF(sp)
        lw      s6, LPP_S6_OFF(sp)
        lw      s7, LPP_S7_OFF(sp)
        lw      s8, LPP_S8_OFF(sp)
        lw      s9, LPP_S9_OFF(sp)
        lw      s10, LPP_S10_OFF(sp)
        lw      s11, LPP_S11_OFF(sp)
        lw      ra, LPP_RA_OFF(sp)
        addi    sp, sp, LPP_FRAME
        ret

.Llpp_read_byte:
        bgeu    s3, s4, .Llpp_read_fail
        lbu     a0, 0(s3)
        addi    s3, s3, 1
        ret
.Llpp_read_fail:
        li      a0, LXMF_ERR_INVAL
        ret

.Llpp_parse_bin8:
        mv      t5, ra
        call    .Llpp_read_byte
        bltz    a0, .Llpp_bin8_fail
        li      t0, LXMF_MSGPACK_BIN8
        bne     a0, t0, .Llpp_bin8_fail
        call    .Llpp_read_byte
        bltz    a0, .Llpp_bin8_fail
        mv      t2, a0
        sub     t3, s4, s3
        bltu    t3, t2, .Llpp_bin8_fail
        mv      a0, s3
        mv      a1, t2
        add     s3, s3, t2
        jr      t5
.Llpp_bin8_fail:
        li      a0, 0
        li      a1, 0
        jr      t5

.Llpp_parse_fields_map:
        mv      s11, ra
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        li      t0, 0x80
        bltu    a0, t0, .Llpp_fields_invalid
        li      t0, 0x8F
        bgeu    t0, a0, .Llpp_fields_fixmap
        li      t0, 0xDE
        beq     a0, t0, .Llpp_fields_map16
        li      t0, 0xDF
        beq     a0, t0, .Llpp_fields_map32
        j       .Llpp_fields_invalid

.Llpp_fields_fixmap:
        andi    s10, a0, 0x0F
        j       .Llpp_fields_entries

.Llpp_fields_map16:
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        slli    s10, a0, 8
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        or      s10, s10, a0
        j       .Llpp_fields_entries

.Llpp_fields_map32:
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        slli    s10, a0, 24
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        slli    t0, a0, 16
        or      s10, s10, t0
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        slli    t0, a0, 8
        or      s10, s10, t0
        call    .Llpp_read_byte
        bltz    a0, .Llpp_fields_invalid
        or      s10, s10, a0

.Llpp_fields_entries:
        call    .Llpp_check_fields_cap
        bltz    a0, .Llpp_fields_return
        beqz    s10, .Llpp_fields_ok
        call    .Llpp_parse_field_scalar
        bltz    a0, .Llpp_fields_return
        call    .Llpp_check_fields_cap
        bltz    a0, .Llpp_fields_return
        call    .Llpp_parse_field_scalar
        bltz    a0, .Llpp_fields_return
        call    .Llpp_check_fields_cap
        bltz    a0, .Llpp_fields_return
        addi    s10, s10, -1
        j       .Llpp_fields_entries

.Llpp_fields_ok:
        li      a0, LXMF_OK
.Llpp_fields_return:
        jr      s11
.Llpp_fields_invalid:
        li      a0, LXMF_ERR_INVAL
        jr      s11

.Llpp_check_fields_cap:
        sub     t0, s3, s6
        li      t1, LXMF_PAYLOAD_MAX_FIELDS
        bltu    t1, t0, .Llpp_fields_overflow
        li      a0, LXMF_OK
        ret
.Llpp_fields_overflow:
        li      a0, LXMF_ERR_OVERFLOW
        ret

.Llpp_parse_field_scalar:
        mv      t5, ra
        call    .Llpp_read_byte
        bltz    a0, .Llpp_scalar_fail
        li      t0, 0x80
        bltu    a0, t0, .Llpp_scalar_ok
        li      t0, 0xA0
        bltu    a0, t0, .Llpp_scalar_special
        li      t0, 0xBF
        bgeu    t0, a0, .Llpp_scalar_fixstr
        j       .Llpp_scalar_special

.Llpp_scalar_fixstr:
        andi    a0, a0, 0x1F
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_special:
        li      t0, LXMF_MSGPACK_NIL
        beq     a0, t0, .Llpp_scalar_ok
        li      t0, 0xC2
        beq     a0, t0, .Llpp_scalar_ok
        li      t0, 0xC3
        beq     a0, t0, .Llpp_scalar_ok
        li      t0, LXMF_MSGPACK_BIN8
        beq     a0, t0, .Llpp_scalar_bin8
        li      t0, LXMF_MSGPACK_UINT8
        beq     a0, t0, .Llpp_scalar_uint8
        li      t0, 0xCD
        beq     a0, t0, .Llpp_scalar_uint16
        li      t0, 0xCE
        beq     a0, t0, .Llpp_scalar_uint32
        li      t0, 0xD9
        beq     a0, t0, .Llpp_scalar_str8
        j       .Llpp_scalar_fail

.Llpp_scalar_bin8:
        call    .Llpp_read_byte
        bltz    a0, .Llpp_scalar_fail
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_str8:
        call    .Llpp_read_byte
        bltz    a0, .Llpp_scalar_fail
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_uint8:
        li      a0, 1
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_uint16:
        li      a0, 2
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_uint32:
        li      a0, 4
        call    .Llpp_skip_len
        jr      t5

.Llpp_scalar_ok:
        li      a0, LXMF_OK
        jr      t5
.Llpp_scalar_fail:
        li      a0, LXMF_ERR_INVAL
        jr      t5

.Llpp_skip_len:
        sub     t0, s4, s3
        bltu    t0, a0, .Llpp_skip_fail
        add     s3, s3, a0
        li      a0, LXMF_OK
        ret
.Llpp_skip_fail:
        li      a0, LXMF_ERR_INVAL
        ret

.Llpp_copy_bytes:
        beqz    a2, .Llpp_copy_done
        lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       .Llpp_copy_bytes
.Llpp_copy_done:
        ret

        .size   lxmf_payload_parse, . - lxmf_payload_parse
