# ============================================================================
# @function:    announce_validate
# @module:      announce
# @inputs:      a0 = announce_rx_t* parsed
# @outputs:     a0 = 0 on valid announce, -1 on invalid input or validation failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       64
# @cycles:      bounded (~identity hash + destination hash + Ed25519 verify)
# @ct:          not-required
# @spec:        milestone-5 announce_validate
# @verify:      proofs/announce/announce_validate_contract.py
# @tests:       tests/announce/test_announce_validate.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Validate a parsed non-ratchet Reticulum HEADER_1 or HEADER_2 announce.
 *
 * The parsed packet is public network input, so validation may branch on
 * malformed fields. The signature check delegates to the verified Ed25519
 * verifier after reconstructing the exact signed byte string:
 *
 *   destination_hash || public_key || name_hash || random_hash || app_data
 */

        .include "announce.S"

        .equ AV_ID_HASH_OFF,    0
        .equ AV_DEST_HASH_OFF,  16
        .equ AV_S0_OFF,         32
        .equ AV_S1_OFF,         36
        .equ AV_S2_OFF,         40
        .equ AV_S3_OFF,         44
        .equ AV_RA_OFF,         60
        .equ AV_FRAME,          64

        .section .text.announce_validate, "ax", @progbits
        .global announce_validate
        .type   announce_validate, @function
announce_validate:
        addi    sp, sp, -AV_FRAME
        sw      s0, AV_S0_OFF(sp)
        sw      s1, AV_S1_OFF(sp)
        sw      s2, AV_S2_OFF(sp)
        sw      s3, AV_S3_OFF(sp)
        sw      ra, AV_RA_OFF(sp)

        mv      s0, a0                  /* announce_rx_t* parsed       */
        beqz    s0, .Lav_fail

        lw      t0, ANNOUNCE_RX_OFF_RAW_LEN(s0)
        li      t1, ANNOUNCE_BASE_RAW_LEN
        bltu    t0, t1, .Lav_fail
        li      t1, ANNOUNCE_RETICULUM_MDU
        bltu    t1, t0, .Lav_fail

        lw      s1, ANNOUNCE_RX_OFF_APP_DATA_LEN(s0)
        li      t1, ANNOUNCE_BASE_RAW_LEN
        sub     t2, t0, t1
        bne     s1, t2, .Lav_try_h2_shape
        lw      t3, ANNOUNCE_RX_OFF_PAYLOAD_LEN(s0)
        li      t1, ANNOUNCE_HEADER_LEN
        sub     t2, t0, t1
        beq     t3, t2, .Lav_shape_ok

.Lav_try_h2_shape:
        li      t1, ANNOUNCE_H2_BASE_RAW_LEN
        bltu    t0, t1, .Lav_fail
        sub     t2, t0, t1
        bne     s1, t2, .Lav_fail
        lw      t3, ANNOUNCE_RX_OFF_PAYLOAD_LEN(s0)
        li      t1, ANNOUNCE_H2_HEADER_LEN
        sub     t2, t0, t1
        bne     t3, t2, .Lav_fail

.Lav_shape_ok:
        li      t1, ANNOUNCE_MAX_APP_DATA
        bltu    t1, s1, .Lav_fail

        lw      s3, ANNOUNCE_RX_OFF_APP_DATA_PTR(s0)
        beqz    s1, .Lav_app_ptr_ok
        beqz    s3, .Lav_fail
.Lav_app_ptr_ok:

        addi    a0, s0, ANNOUNCE_RX_OFF_PUBLIC_KEY
        addi    a1, sp, AV_ID_HASH_OFF
        call    identity_hash

        addi    a0, s0, ANNOUNCE_RX_OFF_NAME_HASH
        addi    a1, sp, AV_ID_HASH_OFF
        addi    a2, sp, AV_DEST_HASH_OFF
        call    destination_hash

        addi    a0, sp, AV_DEST_HASH_OFF
        addi    a1, s0, ANNOUNCE_RX_OFF_DEST_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Lav_memeq
        bnez    a0, .Lav_fail

        la      s2, announce_signed_data

        addi    a0, s0, ANNOUNCE_RX_OFF_DEST_HASH
        addi    a1, s2, ANNOUNCE_SIGNED_OFF_DEST_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Lav_copy_bytes

        addi    a0, s0, ANNOUNCE_RX_OFF_PUBLIC_KEY
        addi    a1, s2, ANNOUNCE_SIGNED_OFF_PUBLIC_KEY
        li      a2, ANNOUNCE_PUBLIC_KEY_SIZE
        call    .Lav_copy_bytes

        addi    a0, s0, ANNOUNCE_RX_OFF_NAME_HASH
        addi    a1, s2, ANNOUNCE_SIGNED_OFF_NAME_HASH
        li      a2, ANNOUNCE_NAME_HASH_SIZE
        call    .Lav_copy_bytes

        addi    a0, s0, ANNOUNCE_RX_OFF_RANDOM_HASH
        addi    a1, s2, ANNOUNCE_SIGNED_OFF_RANDOM_HASH
        li      a2, ANNOUNCE_RANDOM_HASH_SIZE
        call    .Lav_copy_bytes

        beqz    s1, .Lav_signed_data_done
        mv      a0, s3
        addi    a1, s2, ANNOUNCE_SIGNED_OFF_APP_DATA
        mv      a2, s1
        call    .Lav_copy_bytes
.Lav_signed_data_done:

        addi    a0, s0, ANNOUNCE_RX_OFF_SIGNATURE
        mv      a1, s2
        li      t0, ANNOUNCE_SIGNED_FIXED_LEN
        add     a2, t0, s1
        addi    a3, s0, ANNOUNCE_RX_OFF_PUBLIC_KEY
        addi    a3, a3, 32
        call    ed25519_verify
        bnez    a0, .Lav_fail

        li      a0, ANNOUNCE_OK
        j       .Lav_return

.Lav_fail:
        li      a0, ANNOUNCE_ERR_INVAL

.Lav_return:
        lw      s0, AV_S0_OFF(sp)
        lw      s1, AV_S1_OFF(sp)
        lw      s2, AV_S2_OFF(sp)
        lw      s3, AV_S3_OFF(sp)
        lw      ra, AV_RA_OFF(sp)
        addi    sp, sp, AV_FRAME
        ret

.Lav_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Lav_memeq:
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

        .size   announce_validate, . - announce_validate
