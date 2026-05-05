# ============================================================================
# @function:    transport_path_response_cache_update
# @module:      transport
# @inputs:      a0 = valid raw announce ptr, a1 = raw announce len, a2 = learned hops
# @outputs:     a0 = 0 on cached, -1 on invalid/oversize input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s9
# @stack:       64
# @cycles:      bounded (8 cache slots + <=253 byte copy)
# @ct:          not-required
# @spec:        minimal LoRa transport path-response cache
# @verify:      proofs/transport/path_response.py
# @tests:       tests/transport/test_path_response.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

/* Store a bounded HEADER_2 PATH_RESPONSE template for a validated announce.
 *
 * Reticulum path responses rebroadcast the signed announce packet with
 * context PATH_RESPONSE. The route table alone cannot recreate that packet
 * because the random hash, signature, and app data must remain byte-exact.
 */

        .include "announce.S"
        .include "identity.S"
        .include "lora.S"
        .include "packet.S"
        .include "transport.S"

        .equ TPRCU_S0_OFF,  0
        .equ TPRCU_S1_OFF,  4
        .equ TPRCU_S2_OFF,  8
        .equ TPRCU_S3_OFF,  12
        .equ TPRCU_S4_OFF,  16
        .equ TPRCU_S5_OFF,  20
        .equ TPRCU_S6_OFF,  24
        .equ TPRCU_S7_OFF,  28
        .equ TPRCU_S8_OFF,  32
        .equ TPRCU_S9_OFF,  36
        .equ TPRCU_RA_OFF,  60
        .equ TPRCU_FRAME,   64

        .section .text.transport_path_response_cache_update, "ax", @progbits
        .global transport_path_response_cache_update
        .type   transport_path_response_cache_update, @function
transport_path_response_cache_update:
        addi    sp, sp, -TPRCU_FRAME
        sw      s0, TPRCU_S0_OFF(sp)
        sw      s1, TPRCU_S1_OFF(sp)
        sw      s2, TPRCU_S2_OFF(sp)
        sw      s3, TPRCU_S3_OFF(sp)
        sw      s4, TPRCU_S4_OFF(sp)
        sw      s5, TPRCU_S5_OFF(sp)
        sw      s6, TPRCU_S6_OFF(sp)
        sw      s7, TPRCU_S7_OFF(sp)
        sw      s8, TPRCU_S8_OFF(sp)
        sw      s9, TPRCU_S9_OFF(sp)
        sw      ra, TPRCU_RA_OFF(sp)

        mv      s0, a0                  /* raw announce ptr             */
        mv      s1, a1                  /* raw announce len             */
        mv      s2, a2                  /* learned hops                 */
        beqz    s0, .Ltprcu_fail
        li      t0, HEADER_MINSIZE
        bltu    s1, t0, .Ltprcu_fail
        srli    t0, s2, 8
        bnez    t0, .Ltprcu_fail

        lbu     t0, ANNOUNCE_RAW_OFF_FLAGS(s0)
        andi    t0, t0, FLAG_HEADER_TYPE
        beqz    t0, .Ltprcu_h1

        li      t0, HEADER_H2_SIZE
        bltu    s1, t0, .Ltprcu_fail
        li      t0, SX1262_BENCH_PAYLOAD_MAX
        bltu    t0, s1, .Ltprcu_fail
        li      s9, 1                   /* source is HEADER_2           */
        addi    s7, s0, ANNOUNCE_H2_RAW_OFF_DEST_HASH
        mv      s8, s1                  /* output len                   */
        j       .Ltprcu_scan

.Ltprcu_h1:
        li      t0, SX1262_BENCH_PAYLOAD_MAX - HASH_LEN
        bltu    t0, s1, .Ltprcu_fail
        li      s9, 0                   /* source is HEADER_1           */
        addi    s7, s0, ANNOUNCE_RAW_OFF_DEST_HASH
        addi    s8, s1, HASH_LEN        /* H1 -> H2 adds transport id   */

.Ltprcu_scan:
        la      s3, transport_path_response_cache
        mv      s4, zero                /* first invalid slot           */
        li      s6, TRANSPORT_PATH_RESPONSE_CAPACITY
.Ltprcu_scan_slot:
        beqz    s6, .Ltprcu_choose_slot
        lbu     t0, TRANSPORT_PATH_RESPONSE_OFF_VALID(s3)
        beqz    t0, .Ltprcu_note_invalid

        mv      a0, s7
        addi    a1, s3, TRANSPORT_PATH_RESPONSE_OFF_DEST_HASH
        li      a2, HASH_LEN
        call    .Ltprcu_memeq
        bnez    a0, .Ltprcu_found_slot
        j       .Ltprcu_next_slot

.Ltprcu_note_invalid:
        bnez    s4, .Ltprcu_next_slot
        mv      s4, s3

.Ltprcu_next_slot:
        addi    s3, s3, TRANSPORT_PATH_RESPONSE_ENTRY_SIZE
        addi    s6, s6, -1
        j       .Ltprcu_scan_slot

.Ltprcu_choose_slot:
        bnez    s4, .Ltprcu_use_invalid
        la      s5, transport_path_response_cache
        j       .Ltprcu_write_slot

.Ltprcu_use_invalid:
        mv      s5, s4
        j       .Ltprcu_write_slot

.Ltprcu_found_slot:
        mv      s5, s3

.Ltprcu_write_slot:
        li      t0, 1
        sb      t0, TRANSPORT_PATH_RESPONSE_OFF_VALID(s5)
        sb      zero, TRANSPORT_PATH_RESPONSE_OFF_RESERVED(s5)
        sb      zero, 2(s5)
        sb      zero, 3(s5)
        sw      s8, TRANSPORT_PATH_RESPONSE_OFF_RAW_LEN(s5)

        mv      a0, s7
        addi    a1, s5, TRANSPORT_PATH_RESPONSE_OFF_DEST_HASH
        li      a2, HASH_LEN
        call    .Ltprcu_copy_bytes

        addi    s6, s5, TRANSPORT_PATH_RESPONSE_OFF_RAW
        bnez    s9, .Ltprcu_build_h2

.Ltprcu_build_h1:
        li      t0, ANNOUNCE_HEADER2_FLAGS
        sb      t0, ANNOUNCE_RAW_OFF_FLAGS(s6)
        sb      s2, ANNOUNCE_RAW_OFF_HOPS(s6)

        la      a0, identity_current
        addi    a0, a0, IDENTITY_OFF_HASH
        addi    a1, s6, ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID
        li      a2, HASH_LEN
        call    .Ltprcu_copy_bytes

        addi    a0, s0, ANNOUNCE_RAW_OFF_DEST_HASH
        addi    a1, s6, ANNOUNCE_H2_RAW_OFF_DEST_HASH
        addi    a2, s1, -2
        call    .Ltprcu_copy_bytes

        li      t0, TRANSPORT_CONTEXT_PATH_RESPONSE
        sb      t0, ANNOUNCE_H2_RAW_OFF_CONTEXT(s6)
        j       .Ltprcu_ok

.Ltprcu_build_h2:
        mv      a0, s0
        mv      a1, s6
        mv      a2, s1
        call    .Ltprcu_copy_bytes

        li      t0, ANNOUNCE_HEADER2_FLAGS
        sb      t0, ANNOUNCE_RAW_OFF_FLAGS(s6)
        sb      s2, ANNOUNCE_RAW_OFF_HOPS(s6)

        la      a0, identity_current
        addi    a0, a0, IDENTITY_OFF_HASH
        addi    a1, s6, ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID
        li      a2, HASH_LEN
        call    .Ltprcu_copy_bytes

        li      t0, TRANSPORT_CONTEXT_PATH_RESPONSE
        sb      t0, ANNOUNCE_H2_RAW_OFF_CONTEXT(s6)

.Ltprcu_ok:
        li      a0, TRANSPORT_OK
        j       .Ltprcu_return

.Ltprcu_fail:
        li      a0, TRANSPORT_ERR_INVAL

.Ltprcu_return:
        lw      s0, TPRCU_S0_OFF(sp)
        lw      s1, TPRCU_S1_OFF(sp)
        lw      s2, TPRCU_S2_OFF(sp)
        lw      s3, TPRCU_S3_OFF(sp)
        lw      s4, TPRCU_S4_OFF(sp)
        lw      s5, TPRCU_S5_OFF(sp)
        lw      s6, TPRCU_S6_OFF(sp)
        lw      s7, TPRCU_S7_OFF(sp)
        lw      s8, TPRCU_S8_OFF(sp)
        lw      s9, TPRCU_S9_OFF(sp)
        lw      ra, TPRCU_RA_OFF(sp)
        addi    sp, sp, TPRCU_FRAME
        ret

.Ltprcu_copy_bytes:
        beqz    a2, 2f
1:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

.Ltprcu_memeq:
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

        .size   transport_path_response_cache_update, . - transport_path_response_cache_update
