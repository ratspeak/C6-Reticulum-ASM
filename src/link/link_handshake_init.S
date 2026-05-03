# ============================================================================
# @function:    link_handshake_init
# @module:      link
# @inputs:      a0 = destination_hash ptr (16 bytes), a1 = raw packet out ptr, a2 = raw packet capacity
# @outputs:     a0 = raw packet length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s10
# @stack:       64
# @cycles:      bounded (~x25519_keypair + ed25519_keypair + table scan)
# @ct:          required
# @spec:        milestone-6 link_handshake_init
# @verify:      proofs/link/link_handshake_init.py
# @tests:       tests/link/test_link_handshake_init.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Create or refresh a pending initiator-side link entry and emit the current
 * Reticulum link request packet. Existing destination entries are updated in
 * place. Otherwise the first invalid slot is used; when full, the entry with
 * the largest unsigned age (now - last_seen_ms) is evicted.
 */

        .include "link.S"

        .equ LHI_S0_OFF,   0
        .equ LHI_S1_OFF,   4
        .equ LHI_S2_OFF,   8
        .equ LHI_S3_OFF,   12
        .equ LHI_S4_OFF,   16
        .equ LHI_S5_OFF,   20
        .equ LHI_S6_OFF,   24
        .equ LHI_S7_OFF,   28
        .equ LHI_S8_OFF,   32
        .equ LHI_S9_OFF,   36
        .equ LHI_S10_OFF,  40
        .equ LHI_RA_OFF,   60
        .equ LHI_FRAME,    64

        .section .text.link_handshake_init, "ax", @progbits
        .global link_handshake_init
        .type   link_handshake_init, @function
link_handshake_init:
        addi    sp, sp, -LHI_FRAME
        sw      s0, LHI_S0_OFF(sp)
        sw      s1, LHI_S1_OFF(sp)
        sw      s2, LHI_S2_OFF(sp)
        sw      s3, LHI_S3_OFF(sp)
        sw      s4, LHI_S4_OFF(sp)
        sw      s5, LHI_S5_OFF(sp)
        sw      s6, LHI_S6_OFF(sp)
        sw      s7, LHI_S7_OFF(sp)
        sw      s8, LHI_S8_OFF(sp)
        sw      s9, LHI_S9_OFF(sp)
        sw      s10, LHI_S10_OFF(sp)
        sw      ra, LHI_RA_OFF(sp)

        mv      s0, a0                  /* destination_hash ptr        */
        mv      s1, a1                  /* raw packet out              */
        mv      s2, a2                  /* raw packet capacity         */

        beqz    s0, .Llhi_invalid
        beqz    s1, .Llhi_invalid
        li      t0, LINK_REQUEST_RAW_LEN
        bltu    s2, t0, .Llhi_overflow

        call    clock_now_ms
        mv      s7, a0                  /* now_ms                      */

        la      s8, link_table          /* cursor                      */
        li      s9, LINK_TABLE_CAPACITY /* remaining slots             */
        mv      s3, zero                /* chosen existing             */
        mv      s4, zero                /* first invalid               */
        mv      s5, zero                /* oldest entry                */
        mv      s6, zero                /* oldest age                  */

.Llhi_scan:
        beqz    s9, .Llhi_pick

        lbu     t0, LINK_ENTRY_OFF_VALID(s8)
        beqz    t0, .Llhi_invalid_slot

        /* Compare destination hash. */
        mv      t1, s0
        addi    t2, s8, LINK_ENTRY_OFF_DEST_HASH
        li      t3, LINK_DESTINATION_HASH_SIZE
.Llhi_cmp_dest:
        lbu     t4, 0(t1)
        lbu     t5, 0(t2)
        bne     t4, t5, .Llhi_not_same_dest
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        bnez    t3, .Llhi_cmp_dest
        mv      s3, s8
        j       .Llhi_have_entry

.Llhi_not_same_dest:
        lw      t4, LINK_ENTRY_OFF_LAST_SEEN(s8)
        sub     t5, s7, t4              /* unsigned wrap age           */
        beqz    s5, .Llhi_set_oldest
        bltu    s6, t5, .Llhi_set_oldest
        j       .Llhi_next

.Llhi_set_oldest:
        mv      s5, s8
        mv      s6, t5
        j       .Llhi_next

.Llhi_invalid_slot:
        bnez    s4, .Llhi_next
        mv      s4, s8

.Llhi_next:
        addi    s8, s8, LINK_ENTRY_SIZE
        addi    s9, s9, -1
        j       .Llhi_scan

.Llhi_pick:
        bnez    s3, .Llhi_have_entry
        beqz    s4, .Llhi_use_oldest
        mv      s3, s4
        j       .Llhi_have_entry
.Llhi_use_oldest:
        mv      s3, s5

.Llhi_have_entry:
        /* Generate fresh initiator-side ephemeral keys directly in entry. */
        addi    a0, s3, LINK_ENTRY_OFF_LOCAL_X25519_PUB
        addi    a1, s3, LINK_ENTRY_OFF_LOCAL_X25519_SK
        call    x25519_keypair

        addi    a0, s3, LINK_ENTRY_OFF_LOCAL_ED25519_SK
        addi    a1, s3, LINK_ENTRY_OFF_LOCAL_ED25519_PUB
        call    ed25519_keypair

        /* Fixed metadata. Mark valid last, after the key material is present. */
        sw      s7, LINK_ENTRY_OFF_LAST_SEEN(s3)
        li      t0, LINK_STATUS_PENDING
        sb      t0, LINK_ENTRY_OFF_STATUS(s3)
        li      t0, LINK_MODE_AES256_CBC
        sb      t0, LINK_ENTRY_OFF_MODE(s3)
        sb      zero, LINK_ENTRY_OFF_RESERVED(s3)

        mv      a0, s0
        addi    a1, s3, LINK_ENTRY_OFF_DEST_HASH
        li      a2, LINK_DESTINATION_HASH_SIZE
        call    .Llhi_copy_bytes

        addi    a0, s3, LINK_ENTRY_OFF_REMOTE_X25519_PUB
        li      a1, LINK_ENTRY_OFF_KEY_MATERIAL - LINK_ENTRY_OFF_REMOTE_X25519_PUB + LINK_KEY_MATERIAL_SIZE
        call    .Llhi_zero_bytes

        li      t0, 1
        sb      t0, LINK_ENTRY_OFF_VALID(s3)

        mv      a0, s0
        addi    a1, s3, LINK_ENTRY_OFF_LOCAL_X25519_PUB
        addi    a2, s3, LINK_ENTRY_OFF_LOCAL_ED25519_PUB
        mv      a3, s1
        mv      a4, s2
        call    link_request_build
        j       .Llhi_return

.Llhi_overflow:
        li      a0, LINK_ERR_OVERFLOW
        j       .Llhi_return

.Llhi_invalid:
        li      a0, LINK_ERR_INVAL

.Llhi_return:
        lw      s0, LHI_S0_OFF(sp)
        lw      s1, LHI_S1_OFF(sp)
        lw      s2, LHI_S2_OFF(sp)
        lw      s3, LHI_S3_OFF(sp)
        lw      s4, LHI_S4_OFF(sp)
        lw      s5, LHI_S5_OFF(sp)
        lw      s6, LHI_S6_OFF(sp)
        lw      s7, LHI_S7_OFF(sp)
        lw      s8, LHI_S8_OFF(sp)
        lw      s9, LHI_S9_OFF(sp)
        lw      s10, LHI_S10_OFF(sp)
        lw      ra, LHI_RA_OFF(sp)
        addi    sp, sp, LHI_FRAME
        ret

.Llhi_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Llhi_zero_bytes:
        beqz    a1, 4f
3:      sb      zero, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, -1
        bnez    a1, 3b
4:      ret

        .size   link_handshake_init, . - link_handshake_init
