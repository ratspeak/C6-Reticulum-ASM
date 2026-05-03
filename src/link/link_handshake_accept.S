# ============================================================================
# @function:    link_handshake_accept
# @module:      link
# @inputs:      a0 = link_request_t* parsed
# @outputs:     a0 = 0 on established, 1 on duplicate established request, -1 on invalid
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s10
# @stack:       208
# @cycles:      bounded (~table scan + x25519_keypair + scalar_mult + HKDF)
# @ct:          required
# @spec:        milestone-6 link_handshake_accept
# @verify:      proofs/link/link_handshake_accept.py
# @tests:       tests/link/test_link_handshake_accept.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Accept the milestone-6 current Reticulum link request subset.
 *
 * Link ID derivation follows upstream RNS.Link.link_id_from_lr_packet() for a
 * signalled HEADER_1 LINKREQUEST:
 *   SHA256( (flags & 0x0f) || dest_hash || context || x25519_pub ||
 *           ed25519_link_pub )[0:16]
 *
 * The three signalling bytes are intentionally excluded from the link ID.
 */

        .include "link.S"
        .include "sha256.S"

        .equ LHA_HASHABLE_OFF, 0       /* 82 bytes                    */
        .equ LHA_SHARED_OFF,   84      /* 32 bytes                    */
        .equ LHA_DIGEST_OFF,   116     /* 32 bytes                    */
        .equ LHA_S0_OFF,       148
        .equ LHA_S1_OFF,       152
        .equ LHA_S2_OFF,       156
        .equ LHA_S3_OFF,       160
        .equ LHA_S4_OFF,       164
        .equ LHA_S5_OFF,       168
        .equ LHA_S6_OFF,       172
        .equ LHA_S7_OFF,       176
        .equ LHA_S8_OFF,       180
        .equ LHA_S9_OFF,       184
        .equ LHA_S10_OFF,      188
        .equ LHA_RA_OFF,       204
        .equ LHA_FRAME,        208

        .section .text.link_handshake_accept, "ax", @progbits
        .global link_handshake_accept
        .type   link_handshake_accept, @function
link_handshake_accept:
        addi    sp, sp, -LHA_FRAME
        sw      s0, LHA_S0_OFF(sp)
        sw      s1, LHA_S1_OFF(sp)
        sw      s2, LHA_S2_OFF(sp)
        sw      s3, LHA_S3_OFF(sp)
        sw      s4, LHA_S4_OFF(sp)
        sw      s5, LHA_S5_OFF(sp)
        sw      s6, LHA_S6_OFF(sp)
        sw      s7, LHA_S7_OFF(sp)
        sw      s8, LHA_S8_OFF(sp)
        sw      s9, LHA_S9_OFF(sp)
        sw      s10, LHA_S10_OFF(sp)
        sw      ra, LHA_RA_OFF(sp)

        mv      s0, a0                  /* parsed link_request_t       */
        beqz    s0, .Llha_invalid

        lw      t0, LINK_REQUEST_OFF_RAW_LEN(s0)
        li      t1, LINK_REQUEST_RAW_LEN
        bne     t0, t1, .Llha_invalid
        lw      t0, LINK_REQUEST_OFF_MTU(s0)
        li      t1, LINK_DEFAULT_MTU
        bne     t0, t1, .Llha_invalid
        lw      t0, LINK_REQUEST_OFF_MODE(s0)
        li      t1, LINK_MODE_AES256_CBC
        bne     t0, t1, .Llha_invalid

        call    clock_now_ms
        mv      s7, a0

        la      s8, link_table
        li      s9, LINK_TABLE_CAPACITY
        mv      s3, zero                /* chosen existing dest        */
        mv      s4, zero                /* first invalid               */
        mv      s5, zero                /* oldest entry                */
        mv      s6, zero                /* oldest age                  */

.Llha_scan:
        beqz    s9, .Llha_pick

        lbu     t0, LINK_ENTRY_OFF_VALID(s8)
        beqz    t0, .Llha_invalid_slot

        addi    a0, s8, LINK_ENTRY_OFF_DEST_HASH
        addi    a1, s0, LINK_REQUEST_OFF_DEST_HASH
        li      a2, LINK_DESTINATION_HASH_SIZE
        call    .Llha_memeq
        beqz    a0, .Llha_not_same_dest

        lbu     t0, LINK_ENTRY_OFF_STATUS(s8)
        li      t1, LINK_STATUS_ESTABLISHED
        bne     t0, t1, .Llha_choose_same_dest
        addi    a0, s8, LINK_ENTRY_OFF_REMOTE_X25519_PUB
        addi    a1, s0, LINK_REQUEST_OFF_X25519_PUB
        li      a2, LINK_X25519_PUB_SIZE
        call    .Llha_memeq
        beqz    a0, .Llha_choose_same_dest
        sw      s7, LINK_ENTRY_OFF_LAST_SEEN(s8)
        li      a0, LINK_STATUS_DUPLICATE
        j       .Llha_return

.Llha_choose_same_dest:
        mv      s3, s8
        j       .Llha_have_entry

.Llha_not_same_dest:
        lw      t4, LINK_ENTRY_OFF_LAST_SEEN(s8)
        sub     t5, s7, t4
        beqz    s5, .Llha_set_oldest
        bltu    s6, t5, .Llha_set_oldest
        j       .Llha_next

.Llha_set_oldest:
        mv      s5, s8
        mv      s6, t5
        j       .Llha_next

.Llha_invalid_slot:
        bnez    s4, .Llha_next
        mv      s4, s8

.Llha_next:
        addi    s8, s8, LINK_ENTRY_SIZE
        addi    s9, s9, -1
        j       .Llha_scan

.Llha_pick:
        bnez    s3, .Llha_have_entry
        beqz    s4, .Llha_use_oldest
        mv      s3, s4
        j       .Llha_have_entry
.Llha_use_oldest:
        mv      s3, s5

.Llha_have_entry:
        /* Fresh local X25519 material for the accepting side. */
        addi    a0, s3, LINK_ENTRY_OFF_LOCAL_X25519_PUB
        addi    a1, s3, LINK_ENTRY_OFF_LOCAL_X25519_SK
        call    x25519_keypair

        /* shared_secret = X25519(local_sk, remote_x25519_pub) */
        addi    a0, sp, LHA_SHARED_OFF
        addi    a1, s3, LINK_ENTRY_OFF_LOCAL_X25519_SK
        addi    a2, s0, LINK_REQUEST_OFF_X25519_PUB
        call    x25519_scalar_mult

        /* Assemble upstream link-id hashable part. */
        addi    t0, sp, LHA_HASHABLE_OFF
        li      t1, LINK_REQUEST_HEADER_FLAGS
        sb      t1, 0(t0)
        addi    t0, t0, 1
        addi    a0, s0, LINK_REQUEST_OFF_DEST_HASH
        mv      a1, t0
        li      a2, LINK_DESTINATION_HASH_SIZE
        call    .Llha_copy_bytes
        addi    t0, sp, LHA_HASHABLE_OFF + 1 + LINK_DESTINATION_HASH_SIZE
        sb      zero, 0(t0)
        addi    t0, t0, 1
        addi    a0, s0, LINK_REQUEST_OFF_X25519_PUB
        mv      a1, t0
        li      a2, LINK_X25519_PUB_SIZE
        call    .Llha_copy_bytes
        addi    t0, sp, LHA_HASHABLE_OFF + 1 + LINK_DESTINATION_HASH_SIZE + 1 + LINK_X25519_PUB_SIZE
        addi    a0, s0, LINK_REQUEST_OFF_ED25519_PUB
        mv      a1, t0
        li      a2, LINK_ED25519_PUB_SIZE
        call    .Llha_copy_bytes

        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        addi    a1, sp, LHA_HASHABLE_OFF
        li      a2, LINK_REQUEST_ID_HASHABLE_LEN
        call    sha256_update
        la      a0, sha256_ctx
        addi    a1, sp, LHA_DIGEST_OFF
        call    sha256_final

        addi    a0, sp, LHA_DIGEST_OFF
        addi    a1, s3, LINK_ENTRY_OFF_LINK_ID
        li      a2, LINK_ID_SIZE
        call    .Llha_copy_bytes

        addi    a0, sp, LHA_SHARED_OFF
        addi    a1, s3, LINK_ENTRY_OFF_LINK_ID
        li      a2, LINK_ID_SIZE
        addi    a3, s3, LINK_ENTRY_OFF_KEY_MATERIAL
        call    link_derive_keys
        bnez    a0, .Llha_invalid

        /* Store established metadata and remote keys. */
        sw      s7, LINK_ENTRY_OFF_LAST_SEEN(s3)
        li      t0, LINK_STATUS_ESTABLISHED
        sb      t0, LINK_ENTRY_OFF_STATUS(s3)
        li      t0, LINK_MODE_AES256_CBC
        sb      t0, LINK_ENTRY_OFF_MODE(s3)
        sb      zero, LINK_ENTRY_OFF_RESERVED(s3)

        addi    a0, s0, LINK_REQUEST_OFF_DEST_HASH
        addi    a1, s3, LINK_ENTRY_OFF_DEST_HASH
        li      a2, LINK_DESTINATION_HASH_SIZE
        call    .Llha_copy_bytes

        addi    a0, s3, LINK_ENTRY_OFF_LOCAL_ED25519_PUB
        li      a1, LINK_ENTRY_OFF_REMOTE_X25519_PUB - LINK_ENTRY_OFF_LOCAL_ED25519_PUB
        call    .Llha_zero_bytes

        addi    a0, s0, LINK_REQUEST_OFF_X25519_PUB
        addi    a1, s3, LINK_ENTRY_OFF_REMOTE_X25519_PUB
        li      a2, LINK_X25519_PUB_SIZE
        call    .Llha_copy_bytes

        addi    a0, s0, LINK_REQUEST_OFF_ED25519_PUB
        addi    a1, s3, LINK_ENTRY_OFF_REMOTE_ED25519_PUB
        li      a2, LINK_ED25519_PUB_SIZE
        call    .Llha_copy_bytes

        li      t0, 1
        sb      t0, LINK_ENTRY_OFF_VALID(s3)
        li      a0, LINK_OK
        j       .Llha_return

.Llha_invalid:
        li      a0, LINK_ERR_INVAL

.Llha_return:
        lw      s0, LHA_S0_OFF(sp)
        lw      s1, LHA_S1_OFF(sp)
        lw      s2, LHA_S2_OFF(sp)
        lw      s3, LHA_S3_OFF(sp)
        lw      s4, LHA_S4_OFF(sp)
        lw      s5, LHA_S5_OFF(sp)
        lw      s6, LHA_S6_OFF(sp)
        lw      s7, LHA_S7_OFF(sp)
        lw      s8, LHA_S8_OFF(sp)
        lw      s9, LHA_S9_OFF(sp)
        lw      s10, LHA_S10_OFF(sp)
        lw      ra, LHA_RA_OFF(sp)
        addi    sp, sp, LHA_FRAME
        ret

.Llha_memeq:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        lbu     t1, 0(a1)
        bne     t0, t1, 3f
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      li      a0, 1
        ret
3:      mv      a0, zero
        ret

.Llha_copy_bytes:
        beqz    a2, 5f
4:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 4b
5:      ret

.Llha_zero_bytes:
        beqz    a1, 7f
6:      sb      zero, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, -1
        bnez    a1, 6b
7:      ret

        .size   link_handshake_accept, . - link_handshake_accept
