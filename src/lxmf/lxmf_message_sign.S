# ============================================================================
# @function:    lxmf_message_sign
# @module:      lxmf
# @inputs:      a0 = destination hash ptr (16 bytes)
#               a1 = source hash ptr (16 bytes; must match persisted identity)
#               a2 = payload_without_stamp ptr
#               a3 = payload_without_stamp len
#               a4 = signature out ptr (64 bytes)
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s7
# @stack:       672
# @cycles:      bounded (identity load + SHA-256 + Ed25519 sign)
# @ct:          required
# @spec:        milestone-9 message id and signatures; upstream LXMF/LXMessage.py signature surface
# @verify:      proofs/lxmf/lxmf_message_sign.py
# @tests:       tests/lxmf/test_lxmf_message_sign.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Sign the LXMF message surface used by upstream:
 *
 *   signed_part = destination_hash || source_hash ||
 *                 payload_without_stamp || message_id
 *
 * The persisted identity supplies the Ed25519 seed. The caller-provided source
 * hash must match that identity's stored hash so this helper cannot sign a
 * message claiming to be from another source identity.
 */

        .include "lxmf.S"
        .include "identity.S"

        .equ LMS_IDENTITY_OFF, 0
        .equ LMS_MSG_OFF,      160
        .equ LMS_S0_OFF,       624
        .equ LMS_S1_OFF,       628
        .equ LMS_S2_OFF,       632
        .equ LMS_S3_OFF,       636
        .equ LMS_S4_OFF,       640
        .equ LMS_S5_OFF,       644
        .equ LMS_S6_OFF,       648
        .equ LMS_S7_OFF,       652
        .equ LMS_RA_OFF,       668
        .equ LMS_FRAME,        672

        .section .text.lxmf_message_sign, "ax", @progbits
        .global lxmf_message_sign
        .type   lxmf_message_sign, @function
lxmf_message_sign:
        addi    sp, sp, -LMS_FRAME
        sw      s0, LMS_S0_OFF(sp)
        sw      s1, LMS_S1_OFF(sp)
        sw      s2, LMS_S2_OFF(sp)
        sw      s3, LMS_S3_OFF(sp)
        sw      s4, LMS_S4_OFF(sp)
        sw      s5, LMS_S5_OFF(sp)
        sw      s6, LMS_S6_OFF(sp)
        sw      s7, LMS_S7_OFF(sp)
        sw      ra, LMS_RA_OFF(sp)

        mv      s0, a0                  /* destination hash ptr         */
        mv      s1, a1                  /* source hash ptr              */
        mv      s2, a2                  /* payload_without_stamp ptr    */
        mv      s3, a3                  /* payload_without_stamp len    */
        mv      s4, a4                  /* signature out ptr            */
        addi    s5, sp, LMS_IDENTITY_OFF
        addi    s6, sp, LMS_MSG_OFF

        beqz    s0, .Llms_invalid
        beqz    s1, .Llms_invalid
        beqz    s2, .Llms_invalid
        beqz    s3, .Llms_invalid
        beqz    s4, .Llms_invalid
        li      t0, LXMF_PAYLOAD_MAX_LEN
        bltu    t0, s3, .Llms_overflow

        mv      a0, s5
        call    identity_load
        beqz    a0, .Llms_identity_loaded
        li      t0, IDENTITY_ERR_MISSING
        beq     a0, t0, .Llms_missing
        li      t0, IDENTITY_ERR_IO
        beq     a0, t0, .Llms_io
        j       .Llms_invalid

.Llms_identity_loaded:
        addi    t0, s5, IDENTITY_OFF_HASH
        mv      t1, s1
        li      t2, IDENTITY_HASH_SIZE
        li      t3, 0
.Llms_source_cmp:
        beqz    t2, .Llms_source_cmp_done
        lbu     t4, 0(t0)
        lbu     t5, 0(t1)
        xor     t6, t4, t5
        or      t3, t3, t6
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Llms_source_cmp
.Llms_source_cmp_done:
        bnez    t3, .Llms_invalid

        mv      a0, s0
        mv      a1, s6
        li      a2, LXMF_HASH_SIZE
        call    .Llms_copy_bytes

        mv      a0, s1
        addi    a1, s6, 16
        li      a2, LXMF_HASH_SIZE
        call    .Llms_copy_bytes

        mv      a0, s2
        addi    a1, s6, 32
        mv      a2, s3
        call    .Llms_copy_bytes

        addi    t0, s6, 32
        add     t0, t0, s3             /* message_id slot              */
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        mv      a3, s3
        mv      a4, t0
        call    lxmf_message_id
        bnez    a0, .Llms_done

        li      s7, 64
        add     s7, s7, s3             /* signed_part length           */
        mv      a0, s4
        mv      a1, s6
        mv      a2, s7
        addi    a3, s5, IDENTITY_OFF_ED25519_SK
        call    ed25519_sign

        li      a0, LXMF_OK
        j       .Llms_done

.Llms_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llms_done
.Llms_overflow:
        li      a0, LXMF_ERR_OVERFLOW
        j       .Llms_done
.Llms_missing:
        li      a0, LXMF_ERR_MISSING
        j       .Llms_done
.Llms_io:
        li      a0, LXMF_ERR_IO

.Llms_done:
        lw      s0, LMS_S0_OFF(sp)
        lw      s1, LMS_S1_OFF(sp)
        lw      s2, LMS_S2_OFF(sp)
        lw      s3, LMS_S3_OFF(sp)
        lw      s4, LMS_S4_OFF(sp)
        lw      s5, LMS_S5_OFF(sp)
        lw      s6, LMS_S6_OFF(sp)
        lw      s7, LMS_S7_OFF(sp)
        lw      ra, LMS_RA_OFF(sp)
        addi    sp, sp, LMS_FRAME
        ret

.Llms_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   lxmf_message_sign, . - lxmf_message_sign
