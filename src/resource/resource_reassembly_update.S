# ============================================================================
# @function:    resource_reassembly_update
# @module:      resource
# @inputs:      a0 = resource_advertisement_t* adv or 0, a1 = part payload ptr, a2 = part payload len
# @outputs:     a0 = positive reassembly result status, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       80
# @cycles:      bounded (~2 entries * 64 map-hash checks + resource_part_parse)
# @ct:          not-required
# @spec:        milestone-7 resource_reassembly_update
# @verify:      proofs/resource/resource_reassembly.py
# @tests:       tests/resource/test_resource_reassembly_update.py
# @adrs:        0001, 0002, 0005, 0009
# @status:      verified
# ============================================================================

/* Update the fixed in-RAM resource receive table.
 *
 * If a0 is non-null, it is a parsed resource advertisement and this routine
 * creates a receive entry unless the resource hash is already active.
 *
 * If a0 is null, a1/a2 are one decrypted RESOURCE payload. Reticulum RESOURCE
 * packets do not include a part index; like upstream Link.receive(), this
 * routine computes a map hash for each active incoming resource and searches
 * that resource's current receive window.
 */

        .include "resource.S"

        .equ RRU_PART_OFF, 0
        .equ RRU_S0_OFF,  16
        .equ RRU_S1_OFF,  20
        .equ RRU_S2_OFF,  24
        .equ RRU_S3_OFF,  28
        .equ RRU_S4_OFF,  32
        .equ RRU_S5_OFF,  36
        .equ RRU_S6_OFF,  40
        .equ RRU_S7_OFF,  44
        .equ RRU_S8_OFF,  48
        .equ RRU_S9_OFF,  52
        .equ RRU_S10_OFF, 56
        .equ RRU_S11_OFF, 60
        .equ RRU_RA_OFF,  76
        .equ RRU_FRAME,   80

        .section .text.resource_reassembly_update, "ax", @progbits
        .global resource_reassembly_update
        .type   resource_reassembly_update, @function
resource_reassembly_update:
        addi    sp, sp, -RRU_FRAME
        sw      s0, RRU_S0_OFF(sp)
        sw      s1, RRU_S1_OFF(sp)
        sw      s2, RRU_S2_OFF(sp)
        sw      s3, RRU_S3_OFF(sp)
        sw      s4, RRU_S4_OFF(sp)
        sw      s5, RRU_S5_OFF(sp)
        sw      s6, RRU_S6_OFF(sp)
        sw      s7, RRU_S7_OFF(sp)
        sw      s8, RRU_S8_OFF(sp)
        sw      s9, RRU_S9_OFF(sp)
        sw      s10, RRU_S10_OFF(sp)
        sw      s11, RRU_S11_OFF(sp)
        sw      ra, RRU_RA_OFF(sp)

        mv      s0, a0                  /* advertisement ptr or zero    */
        mv      s1, a1                  /* part payload ptr             */
        mv      s2, a2                  /* part payload len             */

        bnez    s0, .Lrru_advertise

/* ------------------------------------------------------------------------- */
/* Receive one RESOURCE part.                                                */
/* ------------------------------------------------------------------------- */
.Lrru_part:
        la      s3, resource_reassembly_table
        li      s4, RESOURCE_REASSEMBLY_CAPACITY

.Lrru_part_entry_loop:
        beqz    s4, .Lrru_invalid
        lbu     t0, RESOURCE_REASM_OFF_VALID(s3)
        beqz    t0, .Lrru_part_next_entry
        lbu     t0, RESOURCE_REASM_OFF_STATUS(s3)
        li      t1, RESOURCE_REASM_STATUS_RECEIVING
        bne     t0, t1, .Lrru_part_next_entry

        mv      a0, s1
        mv      a1, s2
        addi    a2, s3, RESOURCE_REASM_OFF_RANDOM_HASH
        addi    a3, sp, RRU_PART_OFF
        call    resource_part_parse
        bltz    a0, .Lrru_done

        lw      s9, RESOURCE_REASM_OFF_CONSECUTIVE_IDX(s3)
        beqz    s9, .Lrru_scan_start_ready
        addi    s9, s9, -1
.Lrru_scan_start_ready:
        lw      s7, RESOURCE_REASM_OFF_TOTAL_PARTS(s3)
        lbu     t0, RESOURCE_REASM_OFF_WINDOW(s3)
        add     s10, s9, t0
        bltu    s10, s7, .Lrru_window_ready
        mv      s10, s7

.Lrru_window_ready:
        bgeu    s9, s10, .Lrru_part_next_entry

.Lrru_scan_window:
        slli    t0, s9, 2
        addi    t1, s3, RESOURCE_REASM_OFF_HASHMAP
        add     t1, t1, t0
        addi    t2, sp, RRU_PART_OFF + RESOURCE_PART_OFF_MAPHASH
        lbu     t3, 0(t1)
        lbu     t4, 0(t2)
        bne     t3, t4, .Lrru_scan_next
        lbu     t3, 1(t1)
        lbu     t4, 1(t2)
        bne     t3, t4, .Lrru_scan_next
        lbu     t3, 2(t1)
        lbu     t4, 2(t2)
        bne     t3, t4, .Lrru_scan_next
        lbu     t3, 3(t1)
        lbu     t4, 3(t2)
        bne     t3, t4, .Lrru_scan_next
        j       .Lrru_part_match

.Lrru_scan_next:
        addi    s9, s9, 1
        bltu    s9, s10, .Lrru_scan_window

.Lrru_part_next_entry:
        addi    s3, s3, RESOURCE_REASM_ENTRY_SIZE
        addi    s4, s4, -1
        j       .Lrru_part_entry_loop

.Lrru_part_match:
        srli    t0, s9, 3
        andi    t1, s9, 7
        addi    t2, s3, RESOURCE_REASM_OFF_RECEIVED_BITMAP
        add     t2, t2, t0
        lbu     t3, 0(t2)
        li      t4, 1
        sll     t4, t4, t1
        and     t5, t3, t4
        bnez    t5, .Lrru_duplicate
        or      t3, t3, t4
        sb      t3, 0(t2)

        lw      t0, RESOURCE_REASM_OFF_RECEIVED_COUNT(s3)
        addi    t0, t0, 1
        sw      t0, RESOURCE_REASM_OFF_RECEIVED_COUNT(s3)

        lw      t1, RESOURCE_REASM_OFF_CONSECUTIVE_IDX(s3)
.Lrru_advance_consecutive:
        bgeu    t1, s7, .Lrru_store_consecutive
        srli    t2, t1, 3
        andi    t3, t1, 7
        addi    t4, s3, RESOURCE_REASM_OFF_RECEIVED_BITMAP
        add     t4, t4, t2
        lbu     t5, 0(t4)
        li      t6, 1
        sll     t6, t6, t3
        and     t5, t5, t6
        beqz    t5, .Lrru_store_consecutive
        addi    t1, t1, 1
        j       .Lrru_advance_consecutive

.Lrru_store_consecutive:
        sw      t1, RESOURCE_REASM_OFF_CONSECUTIVE_IDX(s3)
        bne     t0, s7, .Lrru_part_accepted
        li      t1, RESOURCE_REASM_STATUS_COMPLETE
        sb      t1, RESOURCE_REASM_OFF_STATUS(s3)
        li      a0, RESOURCE_REASM_RESULT_COMPLETE
        j       .Lrru_done

.Lrru_part_accepted:
        li      a0, RESOURCE_REASM_RESULT_PART_ACCEPTED
        j       .Lrru_done

.Lrru_duplicate:
        li      a0, RESOURCE_REASM_RESULT_DUPLICATE
        j       .Lrru_done

/* ------------------------------------------------------------------------- */
/* Install one parsed advertisement.                                         */
/* ------------------------------------------------------------------------- */
.Lrru_advertise:
        lw      s7, RESOURCE_ADV_OFF_PART_COUNT(s0)
        beqz    s7, .Lrru_invalid
        li      t0, RESOURCE_REASSEMBLY_MAX_PARTS
        bltu    t0, s7, .Lrru_invalid
        lw      t0, RESOURCE_ADV_OFF_HASHMAP_LEN(s0)
        slli    t1, s7, 2
        bne     t0, t1, .Lrru_invalid
        lw      s8, RESOURCE_ADV_OFF_HASHMAP_PTR(s0)
        beqz    s8, .Lrru_invalid

        la      s3, resource_reassembly_table
        li      s4, RESOURCE_REASSEMBLY_CAPACITY
        mv      s5, zero                /* first invalid slot           */

.Lrru_adv_scan:
        beqz    s4, .Lrru_adv_choose
        lbu     t0, RESOURCE_REASM_OFF_VALID(s3)
        beqz    t0, .Lrru_adv_invalid_slot
        addi    a0, s0, RESOURCE_ADV_OFF_RESOURCE_HASH
        addi    a1, s3, RESOURCE_REASM_OFF_RESOURCE_HASH
        li      a2, RESOURCE_HASH_SIZE
        call    .Lrru_memeq
        bnez    a0, .Lrru_duplicate
        j       .Lrru_adv_next

.Lrru_adv_invalid_slot:
        bnez    s5, .Lrru_adv_next
        mv      s5, s3

.Lrru_adv_next:
        addi    s3, s3, RESOURCE_REASM_ENTRY_SIZE
        addi    s4, s4, -1
        j       .Lrru_adv_scan

.Lrru_adv_choose:
        bnez    s5, .Lrru_adv_install
        la      s5, resource_reassembly_table

.Lrru_adv_install:
        mv      a0, s5
        li      a1, RESOURCE_REASM_ENTRY_SIZE
        call    .Lrru_clear_bytes

        li      t0, 1
        sb      t0, RESOURCE_REASM_OFF_VALID(s5)
        li      t0, RESOURCE_REASM_STATUS_RECEIVING
        sb      t0, RESOURCE_REASM_OFF_STATUS(s5)
        li      t0, RESOURCE_REASM_WINDOW_INIT
        sb      t0, RESOURCE_REASM_OFF_WINDOW(s5)
        sw      s7, RESOURCE_REASM_OFF_TOTAL_PARTS(s5)

        addi    a0, s0, RESOURCE_ADV_OFF_RESOURCE_HASH
        addi    a1, s5, RESOURCE_REASM_OFF_RESOURCE_HASH
        li      a2, RESOURCE_HASH_SIZE
        call    .Lrru_copy_bytes

        addi    a0, s0, RESOURCE_ADV_OFF_RANDOM_HASH
        addi    a1, s5, RESOURCE_REASM_OFF_RANDOM_HASH
        li      a2, RESOURCE_RANDOM_HASH_SIZE
        call    .Lrru_copy_bytes

        mv      a0, s8
        addi    a1, s5, RESOURCE_REASM_OFF_HASHMAP
        slli    a2, s7, 2
        call    .Lrru_copy_bytes

        li      a0, RESOURCE_REASM_RESULT_ADVERTISED
        j       .Lrru_done

.Lrru_invalid:
        li      a0, RESOURCE_ERR_INVAL

.Lrru_done:
        lw      s0, RRU_S0_OFF(sp)
        lw      s1, RRU_S1_OFF(sp)
        lw      s2, RRU_S2_OFF(sp)
        lw      s3, RRU_S3_OFF(sp)
        lw      s4, RRU_S4_OFF(sp)
        lw      s5, RRU_S5_OFF(sp)
        lw      s6, RRU_S6_OFF(sp)
        lw      s7, RRU_S7_OFF(sp)
        lw      s8, RRU_S8_OFF(sp)
        lw      s9, RRU_S9_OFF(sp)
        lw      s10, RRU_S10_OFF(sp)
        lw      s11, RRU_S11_OFF(sp)
        lw      ra, RRU_RA_OFF(sp)
        addi    sp, sp, RRU_FRAME
        ret

.Lrru_copy_bytes:
        beqz    a2, .Lrru_copy_done
        lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       .Lrru_copy_bytes
.Lrru_copy_done:
        ret

.Lrru_clear_bytes:
        beqz    a1, .Lrru_clear_done
        sb      zero, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, -1
        j       .Lrru_clear_bytes
.Lrru_clear_done:
        ret

.Lrru_memeq:
        li      t0, 1
.Lrru_memeq_loop:
        beqz    a2, .Lrru_memeq_done
        lbu     t1, 0(a0)
        lbu     t2, 0(a1)
        beq     t1, t2, .Lrru_memeq_next
        li      t0, 0
.Lrru_memeq_next:
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       .Lrru_memeq_loop
.Lrru_memeq_done:
        mv      a0, t0
        ret

        .size   resource_reassembly_update, . - resource_reassembly_update
