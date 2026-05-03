# ============================================================================
# @function:    lxmf_delivery_announce_build
# @module:      lxmf
# @inputs:      a0 = display name ptr, or 0 for nil
#               a1 = display name len
#               a2 = stamp cost; valid costs are 1..254, other values encode nil
#               a3 = app-data out ptr
#               a4 = app-data out capacity
# @outputs:     a0 = app-data length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s5
# @stack:       32
# @cycles:      bounded (<= 255-byte display-name copy)
# @ct:          not-required
# @spec:        milestone-9 delivery announce app-data; upstream LXMF/LXMRouter.py get_announce_app_data()
# @verify:      proofs/lxmf/lxmf_delivery_announce.py
# @tests:       tests/lxmf/test_lxmf_delivery_announce.py
# @adrs:        0001, 0002, 0005, 0006, 0007
# @status:      verified
# ============================================================================

/* Build upstream-compatible LXMF delivery announce app-data:
 *
 *   msgpack([display_name_or_nil, stamp_cost_or_nil])
 *
 * `display_name` is encoded as msgpack bin8 when a pointer is provided, even
 * for zero-length names. A null display-name pointer with len 0 encodes nil.
 * Stamp costs 1..127 encode as positive fixint, 128..254 encode as uint8, and
 * all other values encode nil, matching LXMRouter.get_announce_app_data().
 */

        .include "lxmf.S"

        .equ LDAB_S0_OFF,  0
        .equ LDAB_S1_OFF,  4
        .equ LDAB_S2_OFF,  8
        .equ LDAB_S3_OFF,  12
        .equ LDAB_S4_OFF,  16
        .equ LDAB_S5_OFF,  20
        .equ LDAB_RA_OFF,  28
        .equ LDAB_FRAME,   32

        .section .text.lxmf_delivery_announce_build, "ax", @progbits
        .global lxmf_delivery_announce_build
        .type   lxmf_delivery_announce_build, @function
lxmf_delivery_announce_build:
        addi    sp, sp, -LDAB_FRAME
        sw      s0, LDAB_S0_OFF(sp)
        sw      s1, LDAB_S1_OFF(sp)
        sw      s2, LDAB_S2_OFF(sp)
        sw      s3, LDAB_S3_OFF(sp)
        sw      s4, LDAB_S4_OFF(sp)
        sw      s5, LDAB_S5_OFF(sp)
        sw      ra, LDAB_RA_OFF(sp)

        mv      s0, a0                  /* display name ptr             */
        mv      s1, a1                  /* display name len             */
        mv      s2, a2                  /* stamp cost                   */
        mv      s3, a3                  /* out ptr                      */
        mv      s4, a4                  /* out capacity                 */

        beqz    s3, .Lldab_invalid

        beqz    s0, .Lldab_name_nil
        li      t0, LXMF_DELIVERY_ANNOUNCE_MAX_NAME
        bltu    t0, s1, .Lldab_overflow
        addi    t2, s1, 2              /* name element: bin8 + len + data */
        j       .Lldab_cost_len

.Lldab_name_nil:
        bnez    s1, .Lldab_invalid
        li      t2, 1                  /* name element: nil            */

.Lldab_cost_len:
        li      t3, 1                  /* default cost element: nil or fixint */
        beqz    s2, .Lldab_have_cost_len
        li      t0, 255
        bgeu    s2, t0, .Lldab_have_cost_len
        li      t0, 128
        bltu    s2, t0, .Lldab_have_cost_len
        li      t3, 2                  /* uint8 marker + cost byte     */

.Lldab_have_cost_len:
        addi    s5, t2, 1              /* array header                 */
        add     s5, s5, t3
        bltu    s4, s5, .Lldab_overflow

        li      t0, LXMF_MSGPACK_FIXARRAY2
        sb      t0, 0(s3)
        addi    t4, s3, 1              /* write cursor                 */

        beqz    s0, .Lldab_emit_name_nil
        li      t0, LXMF_MSGPACK_BIN8
        sb      t0, 0(t4)
        sb      s1, 1(t4)
        addi    t4, t4, 2
        mv      a0, s0
        mv      a1, t4
        mv      a2, s1
        call    .Lldab_copy_bytes
        add     t4, t4, s1
        j       .Lldab_emit_cost

.Lldab_emit_name_nil:
        li      t0, LXMF_MSGPACK_NIL
        sb      t0, 0(t4)
        addi    t4, t4, 1

.Lldab_emit_cost:
        beqz    s2, .Lldab_emit_cost_nil
        li      t0, 255
        bgeu    s2, t0, .Lldab_emit_cost_nil
        li      t0, 128
        bltu    s2, t0, .Lldab_emit_cost_fixint
        li      t0, LXMF_MSGPACK_UINT8
        sb      t0, 0(t4)
        sb      s2, 1(t4)
        j       .Lldab_success

.Lldab_emit_cost_fixint:
        sb      s2, 0(t4)
        j       .Lldab_success

.Lldab_emit_cost_nil:
        li      t0, LXMF_MSGPACK_NIL
        sb      t0, 0(t4)

.Lldab_success:
        mv      a0, s5
        j       .Lldab_return

.Lldab_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Lldab_return

.Lldab_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Lldab_return:
        lw      s0, LDAB_S0_OFF(sp)
        lw      s1, LDAB_S1_OFF(sp)
        lw      s2, LDAB_S2_OFF(sp)
        lw      s3, LDAB_S3_OFF(sp)
        lw      s4, LDAB_S4_OFF(sp)
        lw      s5, LDAB_S5_OFF(sp)
        lw      ra, LDAB_RA_OFF(sp)
        addi    sp, sp, LDAB_FRAME
        ret

.Lldab_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   lxmf_delivery_announce_build, . - lxmf_delivery_announce_build
