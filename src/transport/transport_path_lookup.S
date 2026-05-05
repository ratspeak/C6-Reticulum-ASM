# ============================================================================
# @function:    transport_path_lookup
# @module:      transport
# @inputs:      a0 = destination_hash ptr (16 bytes), a1 = transport_path_entry_t* out
# @outputs:     a0 = 0 on found, -1 on invalid input, -2 on missing destination
# @clobbers:    a0..a2, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       32
# @cycles:      bounded (~8 entries * 16-byte compare + one 120-byte copy)
# @ct:          not-required
# @spec:        milestone-5 transport_path_lookup
# @verify:      proofs/transport/path_table.py
# @tests:       tests/transport/test_path_table.py
# @adrs:        0001, 0002, 0005, 0009
# @status:      verified
# ============================================================================

/* Lookup a valid path table entry by destination hash. */

        .include "transport.S"
        .include "announce.S"

        .equ TPL_S0_OFF,  0
        .equ TPL_S1_OFF,  4
        .equ TPL_S2_OFF,  8
        .equ TPL_S3_OFF,  12
        .equ TPL_RA_OFF,  28
        .equ TPL_FRAME,   32

        .section .text.transport_path_lookup, "ax", @progbits
        .global transport_path_lookup
        .type   transport_path_lookup, @function
transport_path_lookup:
        addi    sp, sp, -TPL_FRAME
        sw      s0, TPL_S0_OFF(sp)
        sw      s1, TPL_S1_OFF(sp)
        sw      s2, TPL_S2_OFF(sp)
        sw      s3, TPL_S3_OFF(sp)
        sw      ra, TPL_RA_OFF(sp)

        mv      s0, a0                  /* destination hash ptr         */
        mv      s1, a1                  /* output entry ptr             */
        beqz    s0, .Ltpl_fail
        beqz    s1, .Ltpl_fail

        la      s2, transport_path_table
        li      s3, TRANSPORT_PATH_CAPACITY
.Ltpl_scan:
        beqz    s3, .Ltpl_missing
        lbu     t0, TRANSPORT_PATH_OFF_VALID(s2)
        beqz    t0, .Ltpl_next

        mv      a0, s0
        addi    a1, s2, TRANSPORT_PATH_OFF_DEST_HASH
        li      a2, ANNOUNCE_DESTINATION_HASH_SIZE
        call    .Ltpl_memeq
        beqz    a0, .Ltpl_found

.Ltpl_next:
        addi    s2, s2, TRANSPORT_PATH_ENTRY_SIZE
        addi    s3, s3, -1
        j       .Ltpl_scan

.Ltpl_found:
        mv      a0, s2
        mv      a1, s1
        li      a2, TRANSPORT_PATH_ENTRY_SIZE
        call    .Ltpl_copy_bytes
        li      a0, TRANSPORT_OK
        j       .Ltpl_return

.Ltpl_missing:
        li      a0, TRANSPORT_ERR_NOT_FOUND
        j       .Ltpl_return

.Ltpl_fail:
        li      a0, TRANSPORT_ERR_INVAL

.Ltpl_return:
        lw      s0, TPL_S0_OFF(sp)
        lw      s1, TPL_S1_OFF(sp)
        lw      s2, TPL_S2_OFF(sp)
        lw      s3, TPL_S3_OFF(sp)
        lw      ra, TPL_RA_OFF(sp)
        addi    sp, sp, TPL_FRAME
        ret

.Ltpl_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Ltpl_memeq:
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

        .size   transport_path_lookup, . - transport_path_lookup
