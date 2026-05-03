# ============================================================================
# @function:    lxmf_payload_build
# @module:      lxmf
# @inputs:      a0 = lxmf_payload_input_t*
#               a1 = payload out ptr
#               a2 = payload out capacity
# @outputs:     a0 = payload length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s8
# @stack:       48
# @cycles:      bounded (<= 64-byte title + 255-byte content + 64-byte fields)
# @ct:          not-required
# @spec:        milestone-9 payload codec; upstream LXMF/LXMessage.py payload msgpack
# @verify:      proofs/lxmf/lxmf_payload_build.py
# @tests:       tests/lxmf/test_lxmf_payload_build.py
# @adrs:        0001, 0002, 0005, 0006, 0007
# @status:      verified
# ============================================================================

/* Build the milestone-9 LXMF payload subset:
 *
 *   msgpack([timestamp_f64, title_bin, content_bin, fields_map])
 *
 * The caller supplies timestamp bytes in big-endian IEEE754 order. Title and
 * content are encoded as bin8, matching upstream Python for the bounded lengths
 * accepted here. Fields are either an implicit empty fixmap (`0x80`) or a caller
 * supplied, already-msgpacked map copied byte-for-byte after shallow map-marker
 * validation. Deeper field validation belongs to lxmf_payload_parse.
 */

        .include "lxmf.S"

        .equ LPB_S0_OFF,  0
        .equ LPB_S1_OFF,  4
        .equ LPB_S2_OFF,  8
        .equ LPB_S3_OFF,  12
        .equ LPB_S4_OFF,  16
        .equ LPB_S5_OFF,  20
        .equ LPB_S6_OFF,  24
        .equ LPB_S7_OFF,  28
        .equ LPB_S8_OFF,  32
        .equ LPB_RA_OFF,  44
        .equ LPB_FRAME,   48

        .section .text.lxmf_payload_build, "ax", @progbits
        .global lxmf_payload_build
        .type   lxmf_payload_build, @function
lxmf_payload_build:
        addi    sp, sp, -LPB_FRAME
        sw      s0, LPB_S0_OFF(sp)
        sw      s1, LPB_S1_OFF(sp)
        sw      s2, LPB_S2_OFF(sp)
        sw      s3, LPB_S3_OFF(sp)
        sw      s4, LPB_S4_OFF(sp)
        sw      s5, LPB_S5_OFF(sp)
        sw      s6, LPB_S6_OFF(sp)
        sw      s7, LPB_S7_OFF(sp)
        sw      s8, LPB_S8_OFF(sp)
        sw      ra, LPB_RA_OFF(sp)

        mv      s0, a0                  /* input struct                 */
        mv      s1, a1                  /* out ptr                      */
        mv      s2, a2                  /* out capacity                 */

        beqz    s0, .Llpb_invalid
        beqz    s1, .Llpb_invalid

        lw      s3, LXMF_PAYLOAD_IN_OFF_TIMESTAMP_BE_PTR(s0)
        lw      s4, LXMF_PAYLOAD_IN_OFF_TITLE_PTR(s0)
        lw      s5, LXMF_PAYLOAD_IN_OFF_TITLE_LEN(s0)
        lw      s6, LXMF_PAYLOAD_IN_OFF_CONTENT_PTR(s0)
        lw      s7, LXMF_PAYLOAD_IN_OFF_CONTENT_LEN(s0)
        lw      t5, LXMF_PAYLOAD_IN_OFF_FIELDS_PTR(s0)
        lw      t6, LXMF_PAYLOAD_IN_OFF_FIELDS_LEN(s0)

        beqz    s3, .Llpb_invalid
        bnez    s4, .Llpb_title_ptr_ok
        bnez    s5, .Llpb_invalid
.Llpb_title_ptr_ok:
        bnez    s6, .Llpb_content_ptr_ok
        bnez    s7, .Llpb_invalid
.Llpb_content_ptr_ok:
        bnez    t5, .Llpb_fields_ptr_ok
        bnez    t6, .Llpb_invalid
.Llpb_fields_ptr_ok:

        li      t0, LXMF_PAYLOAD_MAX_TITLE
        bltu    t0, s5, .Llpb_overflow
        li      t0, LXMF_PAYLOAD_MAX_CONTENT
        bltu    t0, s7, .Llpb_overflow
        beqz    t6, .Llpb_fields_empty_len
        li      t0, LXMF_PAYLOAD_MAX_FIELDS
        bltu    t0, t6, .Llpb_overflow
        lbu     t0, 0(t5)
        li      t1, 0x80
        bltu    t0, t1, .Llpb_invalid
        li      t1, 0x8F
        bgeu    t1, t0, .Llpb_have_fields_len
        li      t1, 0xDE
        beq     t0, t1, .Llpb_fields_map16
        li      t1, 0xDF
        beq     t0, t1, .Llpb_fields_map32
        j       .Llpb_invalid
.Llpb_fields_map16:
        li      t1, 3
        bltu    t6, t1, .Llpb_invalid
        j       .Llpb_have_fields_len
.Llpb_fields_map32:
        li      t1, 5
        bltu    t6, t1, .Llpb_invalid
        j       .Llpb_have_fields_len
.Llpb_fields_empty_len:
        li      t6, 1                  /* implicit empty fixmap        */

.Llpb_have_fields_len:
        li      s8, 14                 /* array + f64 marker/data + two bin8 markers/lens */
        add     s8, s8, s5
        add     s8, s8, s7
        add     s8, s8, t6
        li      t0, LXMF_PAYLOAD_MAX_LEN
        bltu    t0, s8, .Llpb_overflow
        bltu    s2, s8, .Llpb_overflow

        li      t0, LXMF_MSGPACK_FIXARRAY4
        sb      t0, 0(s1)
        li      t0, LXMF_MSGPACK_FLOAT64
        sb      t0, 1(s1)

        mv      a0, s3
        addi    a1, s1, 2
        li      a2, 8
        call    .Llpb_copy_bytes

        addi    t4, s1, 10             /* write cursor after timestamp */
        li      t0, LXMF_MSGPACK_BIN8
        sb      t0, 0(t4)
        sb      s5, 1(t4)
        addi    t4, t4, 2
        mv      a0, s4
        mv      a1, t4
        mv      a2, s5
        call    .Llpb_copy_bytes
        add     t4, t4, s5

        li      t0, LXMF_MSGPACK_BIN8
        sb      t0, 0(t4)
        sb      s7, 1(t4)
        addi    t4, t4, 2
        mv      a0, s6
        mv      a1, t4
        mv      a2, s7
        call    .Llpb_copy_bytes
        add     t4, t4, s7

        lw      t5, LXMF_PAYLOAD_IN_OFF_FIELDS_PTR(s0)
        lw      t6, LXMF_PAYLOAD_IN_OFF_FIELDS_LEN(s0)
        beqz    t6, .Llpb_emit_empty_fields
        mv      a0, t5
        mv      a1, t4
        mv      a2, t6
        call    .Llpb_copy_bytes
        j       .Llpb_success

.Llpb_emit_empty_fields:
        li      t0, 0x80
        sb      t0, 0(t4)

.Llpb_success:
        mv      a0, s8
        j       .Llpb_return

.Llpb_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llpb_return

.Llpb_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Llpb_return:
        lw      s0, LPB_S0_OFF(sp)
        lw      s1, LPB_S1_OFF(sp)
        lw      s2, LPB_S2_OFF(sp)
        lw      s3, LPB_S3_OFF(sp)
        lw      s4, LPB_S4_OFF(sp)
        lw      s5, LPB_S5_OFF(sp)
        lw      s6, LPB_S6_OFF(sp)
        lw      s7, LPB_S7_OFF(sp)
        lw      s8, LPB_S8_OFF(sp)
        lw      ra, LPB_RA_OFF(sp)
        addi    sp, sp, LPB_FRAME
        ret

.Llpb_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   lxmf_payload_build, . - lxmf_payload_build
