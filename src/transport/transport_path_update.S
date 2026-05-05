# ============================================================================
# @function:    transport_path_update
# @module:      transport
# @inputs:      a0 = announce_rx_t* valid announce, a1 = interface_id, a2 = hops,
#               a3 = next_hop ptr (16 bytes), or 0 to use destination hash
# @outputs:     a0 = 0 on inserted/updated/evicted, -1 on invalid input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s10
# @stack:       80
# @cycles:      bounded (~8 entries * 16-byte compare + fixed copies)
# @ct:          not-required
# @spec:        milestone-5 transport_path_update
# @verify:      proofs/transport/path_table.py
# @tests:       tests/transport/test_path_table.py
# @adrs:        0001, 0002, 0005, 0009
# @status:      verified
# ============================================================================

/* Insert or update a valid parsed announce in the in-RAM path table.
 *
 * Replacement order:
 *   1. Update an existing destination hash.
 *   2. Insert into the first invalid entry.
 *   3. Evict the entry with the largest unsigned age (now - last_seen_ms).
 */

        .include "announce.S"
        .include "transport.S"

        .equ TPU_ID_HASH_OFF, 0
        .equ TPU_S0_OFF,     16
        .equ TPU_S1_OFF,     20
        .equ TPU_S2_OFF,     24
        .equ TPU_S3_OFF,     28
        .equ TPU_S4_OFF,     32
        .equ TPU_S5_OFF,     36
        .equ TPU_S6_OFF,     40
        .equ TPU_S7_OFF,     44
        .equ TPU_S8_OFF,     48
        .equ TPU_S9_OFF,     52
        .equ TPU_S10_OFF,    56
        .equ TPU_RA_OFF,     76
        .equ TPU_FRAME,      80

        .section .text.transport_path_update, "ax", @progbits
        .global transport_path_update
        .type   transport_path_update, @function
transport_path_update:
        addi    sp, sp, -TPU_FRAME
        sw      s0, TPU_S0_OFF(sp)
        sw      s1, TPU_S1_OFF(sp)
        sw      s2, TPU_S2_OFF(sp)
        sw      s3, TPU_S3_OFF(sp)
        sw      s4, TPU_S4_OFF(sp)
        sw      s5, TPU_S5_OFF(sp)
        sw      s6, TPU_S6_OFF(sp)
        sw      s7, TPU_S7_OFF(sp)
        sw      s8, TPU_S8_OFF(sp)
        sw      s9, TPU_S9_OFF(sp)
        sw      s10, TPU_S10_OFF(sp)
        sw      ra, TPU_RA_OFF(sp)

        mv      s0, a0                  /* announce_rx_t*              */
        mv      s1, a1                  /* interface_id                */
        mv      s2, a2                  /* hops                        */
        mv      s10, a3                 /* next_hop ptr or null        */
        beqz    s0, .Ltpu_fail
        beqz    s1, .Ltpu_fail
        srli    t0, s1, 8
        bnez    t0, .Ltpu_fail
        srli    t0, s2, 8
        bnez    t0, .Ltpu_fail

        addi    a0, s0, ANNOUNCE_RX_OFF_PUBLIC_KEY
        addi    a1, sp, TPU_ID_HASH_OFF
        call    identity_hash
        call    clock_now_ms
        mv      s3, a0                  /* now_ms                      */

        la      s4, transport_path_table
        li      s5, 0                   /* first invalid entry         */
        li      s6, 0                   /* oldest valid entry          */
        li      s7, 0                   /* largest unsigned age        */
        li      s8, TRANSPORT_PATH_CAPACITY
.Ltpu_scan:
        beqz    s8, .Ltpu_choose_slot
        lbu     t0, TRANSPORT_PATH_OFF_VALID(s4)
        beqz    t0, .Ltpu_invalid_slot

        addi    t1, s0, ANNOUNCE_RX_OFF_DEST_HASH
        addi    t2, s4, TRANSPORT_PATH_OFF_DEST_HASH
        li      t3, ANNOUNCE_DESTINATION_HASH_SIZE
        li      t4, 0
1:      lbu     t5, 0(t1)
        lbu     t6, 0(t2)
        xor     t6, t5, t6
        or      t4, t4, t6
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        bnez    t3, 1b
        beqz    t4, .Ltpu_found_existing

        lw      t1, TRANSPORT_PATH_OFF_LAST_SEEN(s4)
        sub     t2, s3, t1
        beqz    s6, .Ltpu_set_oldest
        bltu    s7, t2, .Ltpu_set_oldest
        j       .Ltpu_next

.Ltpu_set_oldest:
        mv      s6, s4
        mv      s7, t2
        j       .Ltpu_next

.Ltpu_invalid_slot:
        bnez    s5, .Ltpu_next
        mv      s5, s4
        j       .Ltpu_next

.Ltpu_found_existing:
        mv      s9, s4
        j       .Ltpu_write_entry

.Ltpu_next:
        addi    s4, s4, TRANSPORT_PATH_ENTRY_SIZE
        addi    s8, s8, -1
        j       .Ltpu_scan

.Ltpu_choose_slot:
        bnez    s5, .Ltpu_use_invalid
        mv      s9, s6
        beqz    s9, .Ltpu_fail
        j       .Ltpu_write_entry

.Ltpu_use_invalid:
        mv      s9, s5

.Ltpu_write_entry:
        li      t0, 1
        sb      t0, TRANSPORT_PATH_OFF_VALID(s9)
        sb      s1, TRANSPORT_PATH_OFF_INTERFACE(s9)
        sb      s2, TRANSPORT_PATH_OFF_HOPS(s9)
        sb      zero, TRANSPORT_PATH_OFF_RESERVED(s9)
        sw      s3, TRANSPORT_PATH_OFF_LAST_SEEN(s9)

        addi    a0, s0, ANNOUNCE_RX_OFF_DEST_HASH
        addi    a1, s9, TRANSPORT_PATH_OFF_DEST_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Ltpu_copy_bytes

        addi    a0, sp, TPU_ID_HASH_OFF
        addi    a1, s9, TRANSPORT_PATH_OFF_IDENTITY_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Ltpu_copy_bytes

        addi    a0, s0, ANNOUNCE_RX_OFF_PUBLIC_KEY
        addi    a1, s9, TRANSPORT_PATH_OFF_PUBLIC_KEY
        li      a2, ANNOUNCE_PUBLIC_KEY_SIZE
        call    .Ltpu_copy_bytes

        bnez    s10, .Ltpu_copy_next_hop
        addi    a0, s0, ANNOUNCE_RX_OFF_DEST_HASH
        j       .Ltpu_next_hop_src_ready
.Ltpu_copy_next_hop:
        mv      a0, s10
.Ltpu_next_hop_src_ready:
        addi    a1, s9, TRANSPORT_PATH_OFF_NEXT_HOP
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Ltpu_copy_bytes

        li      a0, TRANSPORT_OK
        j       .Ltpu_return

.Ltpu_fail:
        li      a0, TRANSPORT_ERR_INVAL

.Ltpu_return:
        lw      s0, TPU_S0_OFF(sp)
        lw      s1, TPU_S1_OFF(sp)
        lw      s2, TPU_S2_OFF(sp)
        lw      s3, TPU_S3_OFF(sp)
        lw      s4, TPU_S4_OFF(sp)
        lw      s5, TPU_S5_OFF(sp)
        lw      s6, TPU_S6_OFF(sp)
        lw      s7, TPU_S7_OFF(sp)
        lw      s8, TPU_S8_OFF(sp)
        lw      s9, TPU_S9_OFF(sp)
        lw      s10, TPU_S10_OFF(sp)
        lw      ra, TPU_RA_OFF(sp)
        addi    sp, sp, TPU_FRAME
        ret

.Ltpu_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   transport_path_update, . - transport_path_update
