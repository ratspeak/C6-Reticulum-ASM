# ============================================================================
# @function:    lxmf_message_verify
# @module:      lxmf
# @inputs:      a0 = destination hash ptr (16 bytes)
#               a1 = source hash ptr (16 bytes)
#               a2 = payload_without_stamp ptr
#               a3 = payload_without_stamp len
#               a4 = signature ptr (64 bytes)
#               a5 = source Ed25519 public key ptr (32 bytes)
# @outputs:     a0 = 0 on valid signature, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s7
# @stack:       496
# @cycles:      bounded (SHA-256 + Ed25519 verify)
# @ct:          not-required
# @spec:        milestone-9 message id and signatures; upstream LXMF/LXMessage.py signature surface
# @verify:      proofs/lxmf/lxmf_message_verify.py
# @tests:       tests/lxmf/test_lxmf_message_verify.py
# @adrs:        0001, 0002, 0005, 0006, 0007, 0009
# @status:      verified
# ============================================================================

/* Verify the LXMF message signature surface used by upstream:
 *
 *   signed_part = destination_hash || source_hash ||
 *                 payload_without_stamp || message_id
 *
 * The caller supplies the recalled source Ed25519 public key. Binding that
 * key to the Reticulum source hash is owned by the caller's source-identity
 * lookup; this helper verifies only the exact LXMF signed byte surface.
 */

        .include "lxmf.S"
        .include "ed25519.S"

        .equ LMV_MSG_OFF, 0
        .equ LMV_S0_OFF,  464
        .equ LMV_S1_OFF,  468
        .equ LMV_S2_OFF,  472
        .equ LMV_S3_OFF,  476
        .equ LMV_S4_OFF,  480
        .equ LMV_S5_OFF,  484
        .equ LMV_S6_OFF,  488
        .equ LMV_RA_OFF,  492
        .equ LMV_FRAME,   496

        .section .text.lxmf_message_verify, "ax", @progbits
        .global lxmf_message_verify
        .type   lxmf_message_verify, @function
lxmf_message_verify:
        addi    sp, sp, -LMV_FRAME
        sw      s0, LMV_S0_OFF(sp)
        sw      s1, LMV_S1_OFF(sp)
        sw      s2, LMV_S2_OFF(sp)
        sw      s3, LMV_S3_OFF(sp)
        sw      s4, LMV_S4_OFF(sp)
        sw      s5, LMV_S5_OFF(sp)
        sw      s6, LMV_S6_OFF(sp)
        sw      ra, LMV_RA_OFF(sp)

        mv      s0, a0                  /* destination hash ptr         */
        mv      s1, a1                  /* source hash ptr              */
        mv      s2, a2                  /* payload_without_stamp ptr    */
        mv      s3, a3                  /* payload_without_stamp len    */
        mv      s4, a4                  /* signature ptr                */
        mv      s5, a5                  /* source ed25519 public key    */
        addi    s6, sp, LMV_MSG_OFF

        beqz    s0, .Llmv_invalid
        beqz    s1, .Llmv_invalid
        beqz    s2, .Llmv_invalid
        beqz    s3, .Llmv_invalid
        beqz    s4, .Llmv_invalid
        beqz    s5, .Llmv_invalid
        li      t0, LXMF_PAYLOAD_MAX_LEN
        bltu    t0, s3, .Llmv_overflow

        mv      a0, s0
        mv      a1, s6
        li      a2, LXMF_HASH_SIZE
        call    .Llmv_copy_bytes

        mv      a0, s1
        addi    a1, s6, 16
        li      a2, LXMF_HASH_SIZE
        call    .Llmv_copy_bytes

        mv      a0, s2
        addi    a1, s6, 32
        mv      a2, s3
        call    .Llmv_copy_bytes

        addi    t0, s6, 32
        add     t0, t0, s3             /* message_id slot              */
        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        mv      a3, s3
        mv      a4, t0
        call    lxmf_message_id
        bnez    a0, .Llmv_done

        li      a2, 64
        add     a2, a2, s3             /* signed_part length           */
        mv      a0, s4
        mv      a1, s6
        mv      a3, s5
        call    ed25519_verify
        beqz    a0, .Llmv_ok
        li      a0, LXMF_ERR_BAD_SIGNATURE
        j       .Llmv_done

.Llmv_ok:
        li      a0, LXMF_OK
        j       .Llmv_done
.Llmv_invalid:
        li      a0, LXMF_ERR_INVAL
        j       .Llmv_done
.Llmv_overflow:
        li      a0, LXMF_ERR_OVERFLOW

.Llmv_done:
        lw      s0, LMV_S0_OFF(sp)
        lw      s1, LMV_S1_OFF(sp)
        lw      s2, LMV_S2_OFF(sp)
        lw      s3, LMV_S3_OFF(sp)
        lw      s4, LMV_S4_OFF(sp)
        lw      s5, LMV_S5_OFF(sp)
        lw      s6, LMV_S6_OFF(sp)
        lw      ra, LMV_RA_OFF(sp)
        addi    sp, sp, LMV_FRAME
        ret

.Llmv_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   lxmf_message_verify, . - lxmf_message_verify
