# ============================================================================
# @function:    lxmf_message_pack
# @module:      lxmf
# @inputs:      a0 = destination hash ptr (16 bytes)
#               a1 = source hash ptr (16 bytes; must match persisted identity)
#               a2 = lxmf_payload_input_t*
#               a3 = packed message out ptr
#               a4 = packed message out capacity
# @outputs:     a0 = packed message length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s5
# @stack:       32
# @cycles:      bounded (payload build + identity load + SHA-256 + Ed25519 sign)
# @ct:          required
# @spec:        milestone-9 message envelope codec; upstream LXMF/LXMessage.py pack
# @verify:      proofs/lxmf/lxmf_message_pack.py
# @tests:       tests/lxmf/test_lxmf_message_pack.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Pack the milestone-9 LXMF message subset:
 *
 *   destination_hash || source_hash || signature || payload
 *
 * Payload construction remains in lxmf_payload_build. The signature is over
 * destination_hash || source_hash || payload || message_id, matching upstream
 * LXMessage.pack(). This helper does not add Reticulum packet framing.
 */

        .include "lxmf.S"

        .equ LMP_S0_OFF,  0
        .equ LMP_S1_OFF,  4
        .equ LMP_S2_OFF,  8
        .equ LMP_S3_OFF,  12
        .equ LMP_S4_OFF,  16
        .equ LMP_S5_OFF,  20
        .equ LMP_RA_OFF,  28
        .equ LMP_FRAME,   32

        .section .text.lxmf_message_pack, "ax", @progbits
        .global lxmf_message_pack
        .type   lxmf_message_pack, @function
lxmf_message_pack:
        addi    sp, sp, -LMP_FRAME
        sw      s0, LMP_S0_OFF(sp)
        sw      s1, LMP_S1_OFF(sp)
        sw      s2, LMP_S2_OFF(sp)
        sw      s3, LMP_S3_OFF(sp)
        sw      s4, LMP_S4_OFF(sp)
        sw      s5, LMP_S5_OFF(sp)
        sw      ra, LMP_RA_OFF(sp)

        mv      s0, a0                  /* destination hash ptr         */
        mv      s1, a1                  /* source hash ptr              */
        mv      s2, a2                  /* payload input struct         */
        mv      s3, a3                  /* packed out ptr               */
        mv      s4, a4                  /* packed out capacity          */

        beqz    s0, .Llmp_invalid
        beqz    s1, .Llmp_invalid
        beqz    s2, .Llmp_invalid
        beqz    s3, .Llmp_invalid

        li      t0, LXMF_PACKED_PREFIX_SIZE
        bltu    s4, t0, .Llmp_overflow

        mv      a0, s2
        addi    a1, s3, LXMF_PACKED_PREFIX_SIZE
        sub     a2, s4, t0
        call    lxmf_payload_build
        blt     a0, zero, .Llmp_done
        mv      s5, a0                  /* payload length               */

        mv      a0, s0
        mv      a1, s3
        li      a2, LXMF_HASH_SIZE
        call    .Llmp_copy_bytes

        mv      a0, s1
        addi    a1, s3, LXMF_HASH_SIZE
        li      a2, LXMF_HASH_SIZE
        call    .Llmp_copy_bytes

        mv      a0, s0
        mv      a1, s1
        addi    a2, s3, LXMF_PACKED_PREFIX_SIZE
        mv      a3, s5
        addi    a4, s3, LXMF_SIGNING_PREFIX_SIZE
        call    lxmf_message_sign
        bnez    a0, .Llmp_done

        li      a0, LXMF_PACKED_PREFIX_SIZE
        add     a0, a0, s5
        j       .Llmp_done

.Llmp_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llmp_done
.Llmp_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Llmp_done:
        lw      s0, LMP_S0_OFF(sp)
        lw      s1, LMP_S1_OFF(sp)
        lw      s2, LMP_S2_OFF(sp)
        lw      s3, LMP_S3_OFF(sp)
        lw      s4, LMP_S4_OFF(sp)
        lw      s5, LMP_S5_OFF(sp)
        lw      ra, LMP_RA_OFF(sp)
        addi    sp, sp, LMP_FRAME
        ret

.Llmp_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   lxmf_message_pack, . - lxmf_message_pack
