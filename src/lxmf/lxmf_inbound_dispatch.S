# ============================================================================
# @function:    lxmf_inbound_dispatch
# @module:      lxmf
# @inputs:      a0 = inbound payload ptr
#               a1 = inbound payload len
#               a2 = packet destination hash ptr (opportunistic mode only)
#               a3 = dispatch mode (0 direct, 1 opportunistic)
#               a4 = direct link established flag
# @outputs:     a0 = delivered/duplicate status or negative errno
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       1232
# @cycles:      bounded (path lookup + payload parse + SHA-256 + Ed25519 verify)
# @ct:          not-required
# @spec:        milestone-9 inbound delivery dispatch
# @verify:      proofs/lxmf/lxmf_inbound_dispatch.py
# @tests:       tests/lxmf/test_lxmf_inbound_dispatch.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Dispatch one inbound LXMF message into the single milestone-9 slot.
 *
 * Direct mode requires an established link and receives the full packed LXMF
 * message. Opportunistic mode receives the Reticulum packet payload, where the
 * leading destination hash has been stripped, so this helper prefixes the
 * packet destination hash before parsing. Source identity recall is represented
 * by the transport path table: the packed source hash must have a path entry
 * containing the source identity public key.
 */

        .include "lxmf.S"
        .include "transport.S"

        .equ LID_PACKED_OFF,   0
        .equ LID_PARSED_OFF,   528
        .equ LID_ENTRY_OFF,    1044
        .equ LID_S0_OFF,       1168
        .equ LID_S1_OFF,       1172
        .equ LID_S2_OFF,       1176
        .equ LID_S3_OFF,       1180
        .equ LID_S4_OFF,       1184
        .equ LID_S5_OFF,       1188
        .equ LID_S6_OFF,       1192
        .equ LID_S7_OFF,       1196
        .equ LID_S8_OFF,       1200
        .equ LID_S9_OFF,       1204
        .equ LID_S10_OFF,      1208
        .equ LID_S11_OFF,      1212
        .equ LID_RA_OFF,       1228
        .equ LID_FRAME,        1232

        .section .text.lxmf_inbound_dispatch, "ax", @progbits
        .global lxmf_inbound_dispatch
        .type   lxmf_inbound_dispatch, @function
lxmf_inbound_dispatch:
        addi    sp, sp, -LID_FRAME
        sw      s0, LID_S0_OFF(sp)
        sw      s1, LID_S1_OFF(sp)
        sw      s2, LID_S2_OFF(sp)
        sw      s3, LID_S3_OFF(sp)
        sw      s4, LID_S4_OFF(sp)
        sw      s5, LID_S5_OFF(sp)
        sw      s6, LID_S6_OFF(sp)
        sw      s7, LID_S7_OFF(sp)
        sw      s8, LID_S8_OFF(sp)
        sw      s9, LID_S9_OFF(sp)
        sw      s10, LID_S10_OFF(sp)
        sw      s11, LID_S11_OFF(sp)
        sw      ra, LID_RA_OFF(sp)

        mv      s0, a0                  /* inbound payload ptr          */
        mv      s1, a1                  /* inbound payload len          */
        mv      s2, a2                  /* packet destination hash      */
        mv      s3, a3                  /* dispatch mode                */
        mv      s4, a4                  /* direct link established      */
        addi    s7, sp, LID_PARSED_OFF
        addi    s8, sp, LID_ENTRY_OFF

        beqz    s0, .Llid_invalid

        li      t0, LXMF_DISPATCH_MODE_DIRECT
        beq     s3, t0, .Llid_direct
        li      t0, LXMF_DISPATCH_MODE_OPPORTUNISTIC
        beq     s3, t0, .Llid_opportunistic
        j       .Llid_invalid

.Llid_direct:
        beqz    s4, .Llid_no_link
        mv      s5, s0                  /* full packed ptr              */
        mv      s6, s1                  /* full packed len              */
        j       .Llid_common

.Llid_opportunistic:
        beqz    s2, .Llid_invalid
        li      t0, LXMF_PACKED_MAX_STAMPED_LEN - LXMF_HASH_SIZE
        bltu    t0, s1, .Llid_capacity
        addi    s5, sp, LID_PACKED_OFF
        mv      a0, s2
        mv      a1, s5
        li      a2, LXMF_HASH_SIZE
        call    .Llid_copy_bytes
        mv      a0, s0
        addi    a1, s5, LXMF_HASH_SIZE
        mv      a2, s1
        call    .Llid_copy_bytes
        addi    s6, s1, LXMF_HASH_SIZE

.Llid_common:
        li      t0, LXMF_PACKED_PREFIX_SIZE
        bltu    s6, t0, .Llid_short
        li      t0, LXMF_PACKED_MAX_STAMPED_LEN
        bltu    t0, s6, .Llid_capacity

        addi    a0, s5, LXMF_HASH_SIZE
        mv      a1, s8
        call    transport_path_lookup
        beqz    a0, .Llid_source_known
        li      t0, TRANSPORT_ERR_NOT_FOUND
        beq     a0, t0, .Llid_unknown_source
        j       .Llid_invalid

.Llid_source_known:
        mv      a0, s5
        mv      a1, s6
        mv      a2, s7
        addi    a3, s8, TRANSPORT_PATH_OFF_PUBLIC_KEY + 32
        call    lxmf_message_parse
        beqz    a0, .Llid_parsed
        li      t0, LXMF_ERR_OVERFLOW
        beq     a0, t0, .Llid_capacity
        j       .Llid_done

.Llid_parsed:
        la      s9, lxmf_inbound_slot_valid
        lbu     t0, 0(s9)
        beqz    t0, .Llid_store

        la      a0, lxmf_inbound_message_id
        addi    a1, s7, LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID
        li      a2, LXMF_MESSAGE_ID_SIZE
        call    .Llid_memeq
        beqz    a0, .Llid_duplicate
        j       .Llid_capacity

.Llid_store:
        addi    a0, s7, LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID
        la      a1, lxmf_inbound_message_id
        li      a2, LXMF_MESSAGE_ID_SIZE
        call    .Llid_copy_bytes

        mv      a0, s5
        la      a1, lxmf_inbound_dest_hash
        li      a2, LXMF_HASH_SIZE
        call    .Llid_copy_bytes

        addi    a0, s5, LXMF_HASH_SIZE
        la      a1, lxmf_inbound_source_hash
        li      a2, LXMF_HASH_SIZE
        call    .Llid_copy_bytes

        lw      t0, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_LEN(s7)
        la      t1, lxmf_inbound_payload_len
        sw      t0, 0(t1)

        li      t0, 1
        sb      t0, 0(s9)
        li      a0, LXMF_OK
        j       .Llid_done

.Llid_duplicate:
        li      a0, LXMF_STATUS_DUPLICATE
        j       .Llid_done
.Llid_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llid_done
.Llid_short:
        li      a0, LXMF_ERR_SHORT
        j       .Llid_done
.Llid_unknown_source:
        li      a0, LXMF_ERR_UNKNOWN_SOURCE
        j       .Llid_done
.Llid_capacity:
        li      a0, LXMF_ERR_CAPACITY
        j       .Llid_done
.Llid_no_link:
        li      a0, LXMF_ERR_NO_LINK

.Llid_done:
        lw      s0, LID_S0_OFF(sp)
        lw      s1, LID_S1_OFF(sp)
        lw      s2, LID_S2_OFF(sp)
        lw      s3, LID_S3_OFF(sp)
        lw      s4, LID_S4_OFF(sp)
        lw      s5, LID_S5_OFF(sp)
        lw      s6, LID_S6_OFF(sp)
        lw      s7, LID_S7_OFF(sp)
        lw      s8, LID_S8_OFF(sp)
        lw      s9, LID_S9_OFF(sp)
        lw      s10, LID_S10_OFF(sp)
        lw      s11, LID_S11_OFF(sp)
        lw      ra, LID_RA_OFF(sp)
        addi    sp, sp, LID_FRAME
        ret

.Llid_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Llid_memeq:
        li      t0, 0
        beqz    a2, 2f
1:      lbu     t1, 0(a0)
        lbu     t2, 0(a1)
        xor     t3, t1, t2
        or      t0, t0, t3
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      snez    a0, t0
        ret

        .size   lxmf_inbound_dispatch, . - lxmf_inbound_dispatch
