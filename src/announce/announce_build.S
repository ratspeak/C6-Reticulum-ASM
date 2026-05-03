# ============================================================================
# @function:    announce_build
# @module:      announce
# @inputs:      a0 = identity_t*, a1 = name_hash ptr (10 bytes), a2 = app_data ptr (may be 0 when app_data_len = 0), a3 = app_data_len, a4 = raw_packet_out ptr, a5 = raw_packet_capacity
# @outputs:     a0 = raw packet length on success, -1 on overflow or invalid input; raw_packet_out filled with HEADER_1 announce packet
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s8
# @stack:       48
# @cycles:      bounded (destination_hash + rng_bytes(10) + ed25519_sign + fixed/app_data copies)
# @ct:          required
# @spec:        milestone-3 announce_build; upstream Reticulum HEADER_1 announce construction
# @verify:      proofs/announce/announce_tx.tla
# @tests:       tests/announce/test_announce_build.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Build a non-ratchet Reticulum HEADER_1 announce packet.
 *
 * Inputs are the canonical identity_t layout, a precomputed 10-byte
 * destination name hash, optional app data, and a caller-owned raw packet
 * output buffer. All large temporary data lives in src/state/announce.S.
 *
 * Signed data:
 *   destination_hash || public_key || name_hash || random_hash || app_data
 *
 * Raw packet:
 *   0x01 || 0x00 || destination_hash || 0x00 ||
 *   public_key || name_hash || random_hash || signature || app_data
 */

        .include "announce.S"
        .include "destination.S"
        .include "identity.S"

        .equ AB_S0_OFF,  0
        .equ AB_S1_OFF,  4
        .equ AB_S2_OFF,  8
        .equ AB_S3_OFF,  12
        .equ AB_S4_OFF,  16
        .equ AB_S5_OFF,  20
        .equ AB_S6_OFF,  24
        .equ AB_S7_OFF,  28
        .equ AB_S8_OFF,  32
        .equ AB_RA_OFF,  44
        .equ AB_FRAME,   48

        .section .text.announce_build, "ax", @progbits
        .global announce_build
        .type   announce_build, @function
announce_build:
        addi    sp, sp, -AB_FRAME
        sw      s0, AB_S0_OFF(sp)
        sw      s1, AB_S1_OFF(sp)
        sw      s2, AB_S2_OFF(sp)
        sw      s3, AB_S3_OFF(sp)
        sw      s4, AB_S4_OFF(sp)
        sw      s5, AB_S5_OFF(sp)
        sw      s6, AB_S6_OFF(sp)
        sw      s7, AB_S7_OFF(sp)
        sw      s8, AB_S8_OFF(sp)
        sw      ra, AB_RA_OFF(sp)

        mv      s0, a0                  /* identity_t*                 */
        mv      s1, a1                  /* name_hash ptr               */
        mv      s2, a2                  /* app_data ptr                */
        mv      s3, a3                  /* app_data_len                */
        mv      s4, a4                  /* raw_packet_out              */

        /* Basic invalid-input and capacity checks before consuming RNG. */
        beqz    s0, .Lab_fail
        beqz    s1, .Lab_fail
        beqz    s4, .Lab_fail
        beqz    s3, .Lab_app_ptr_ok
        beqz    s2, .Lab_fail
.Lab_app_ptr_ok:
        li      t0, ANNOUNCE_MAX_APP_DATA
        bltu    t0, s3, .Lab_fail       /* app_data_len > max          */

        li      t0, ANNOUNCE_BASE_RAW_LEN
        add     s5, t0, s3              /* raw_len                     */
        bltu    a5, s5, .Lab_fail       /* capacity < raw_len          */

        la      s6, announce_signed_data
        la      s7, announce_destination_hash
        la      s8, announce_random_hash

        /* destination_hash(name_hash, identity.hash, announce_destination_hash) */
        mv      a0, s1
        addi    a1, s0, IDENTITY_OFF_HASH
        mv      a2, s7
        call    destination_hash

        /* random_hash[10] = rng_bytes(10) */
        mv      a0, s8
        li      a1, ANNOUNCE_RANDOM_HASH_SIZE
        call    rng_bytes

        /* Assemble signed data. */
        mv      a0, s7
        addi    a1, s6, ANNOUNCE_SIGNED_OFF_DEST_HASH
        li      a2, DESTINATION_HASH_SIZE
        call    .Lab_copy_bytes

        addi    a0, s0, IDENTITY_OFF_X25519_PK
        addi    a1, s6, ANNOUNCE_SIGNED_OFF_PUBLIC_KEY
        li      a2, IDENTITY_PUBLIC_KEY_SIZE
        call    .Lab_copy_bytes

        mv      a0, s1
        addi    a1, s6, ANNOUNCE_SIGNED_OFF_NAME_HASH
        li      a2, DESTINATION_NAME_HASH_SIZE
        call    .Lab_copy_bytes

        mv      a0, s8
        addi    a1, s6, ANNOUNCE_SIGNED_OFF_RANDOM_HASH
        li      a2, ANNOUNCE_RANDOM_HASH_SIZE
        call    .Lab_copy_bytes

        beqz    s3, .Lab_signed_app_done
        mv      a0, s2
        addi    a1, s6, ANNOUNCE_SIGNED_OFF_APP_DATA
        mv      a2, s3
        call    .Lab_copy_bytes
.Lab_signed_app_done:

        /* signature = ed25519_sign(signed_data, identity.ed25519_seed) */
        la      a0, announce_signature
        mv      a1, s6
        li      t0, ANNOUNCE_SIGNED_FIXED_LEN
        add     a2, t0, s3
        addi    a3, s0, IDENTITY_OFF_ED25519_SK
        call    ed25519_sign

        /* Raw HEADER_1 packet prefix. */
        li      t0, ANNOUNCE_HEADER_FLAGS
        sb      t0, ANNOUNCE_RAW_OFF_FLAGS(s4)
        sb      zero, ANNOUNCE_RAW_OFF_HOPS(s4)
        sb      zero, ANNOUNCE_RAW_OFF_CONTEXT(s4)

        mv      a0, s7
        addi    a1, s4, ANNOUNCE_RAW_OFF_DEST_HASH
        li      a2, DESTINATION_HASH_SIZE
        call    .Lab_copy_bytes

        addi    a0, s0, IDENTITY_OFF_X25519_PK
        addi    a1, s4, ANNOUNCE_RAW_OFF_PUBLIC_KEY
        li      a2, IDENTITY_PUBLIC_KEY_SIZE
        call    .Lab_copy_bytes

        mv      a0, s1
        addi    a1, s4, ANNOUNCE_RAW_OFF_NAME_HASH
        li      a2, DESTINATION_NAME_HASH_SIZE
        call    .Lab_copy_bytes

        mv      a0, s8
        addi    a1, s4, ANNOUNCE_RAW_OFF_RANDOM_HASH
        li      a2, ANNOUNCE_RANDOM_HASH_SIZE
        call    .Lab_copy_bytes

        la      a0, announce_signature
        addi    a1, s4, ANNOUNCE_RAW_OFF_SIGNATURE
        li      a2, ANNOUNCE_SIGNATURE_SIZE
        call    .Lab_copy_bytes

        beqz    s3, .Lab_success
        mv      a0, s2
        addi    a1, s4, ANNOUNCE_RAW_OFF_APP_DATA
        mv      a2, s3
        call    .Lab_copy_bytes

.Lab_success:
        mv      a0, s5
        j       .Lab_return

.Lab_fail:
        li      a0, -1

.Lab_return:
        lw      s0, AB_S0_OFF(sp)
        lw      s1, AB_S1_OFF(sp)
        lw      s2, AB_S2_OFF(sp)
        lw      s3, AB_S3_OFF(sp)
        lw      s4, AB_S4_OFF(sp)
        lw      s5, AB_S5_OFF(sp)
        lw      s6, AB_S6_OFF(sp)
        lw      s7, AB_S7_OFF(sp)
        lw      s8, AB_S8_OFF(sp)
        lw      ra, AB_RA_OFF(sp)
        addi    sp, sp, AB_FRAME
        ret

.Lab_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   announce_build, . - announce_build
