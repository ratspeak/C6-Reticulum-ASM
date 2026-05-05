# ============================================================================
# @function:    transport_packet_seen
# @module:      transport
# @inputs:      a0 = raw packet ptr, a1 = raw packet len
# @outputs:     a0 = TRANSPORT_OK for new/stored, TRANSPORT_STATUS_DUPLICATE if already seen,
#                    TRANSPORT_ERR_INVAL on malformed input
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s8
# @stack:       224
# @cycles:      bounded (~2 SHA-256 updates plus 16 hash comparisons)
# @ct:          not-required
# @spec:        upstream Transport.packet_hashlist / Packet.get_hashable_part
# @verify:      proofs/transport/transport_packet_seen.py
# @tests:       tests/transport/test_transport_packet_seen.py
# @adrs:        0001, 0002, 0004, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

/* Reticulum packet dedupe over the packet hashable part:
 *
 *   hashable = (flags & 0x0f) || raw[2:]      for HEADER_1
 *   hashable = (flags & 0x0f) || raw[18:]     for HEADER_2
 *
 * This intentionally ignores hop count and HEADER_2 transport_id, matching
 * upstream Packet.get_hashable_part(), so the same payload is recognised
 * across transport-header rewrites.
 */

        .include "packet.S"
        .include "sha256.S"
        .include "transport.S"

        .equ TPH_PKT_OFF,     0
        .equ TPH_CTX_OFF,     32
        .equ TPH_DIGEST_OFF,  144
        .equ TPH_HEAD_OFF,    176
        .equ TPH_S0_OFF,      180
        .equ TPH_S1_OFF,      184
        .equ TPH_S2_OFF,      188
        .equ TPH_S3_OFF,      192
        .equ TPH_S4_OFF,      196
        .equ TPH_S5_OFF,      200
        .equ TPH_S6_OFF,      204
        .equ TPH_S7_OFF,      208
        .equ TPH_S8_OFF,      212
        .equ TPH_RA_OFF,      220
        .equ TPH_FRAME,       224

        .section .text.transport_packet_seen, "ax", @progbits
        .global transport_packet_seen
        .type   transport_packet_seen, @function
transport_packet_seen:
        addi    sp, sp, -TPH_FRAME
        sw      s0, TPH_S0_OFF(sp)
        sw      s1, TPH_S1_OFF(sp)
        sw      s2, TPH_S2_OFF(sp)
        sw      s3, TPH_S3_OFF(sp)
        sw      s4, TPH_S4_OFF(sp)
        sw      s5, TPH_S5_OFF(sp)
        sw      s6, TPH_S6_OFF(sp)
        sw      s7, TPH_S7_OFF(sp)
        sw      s8, TPH_S8_OFF(sp)
        sw      ra, TPH_RA_OFF(sp)

        mv      s0, a0                  /* raw packet ptr              */
        mv      s1, a1                  /* raw packet len              */
        beqz    s0, .Ltph_invalid

        mv      a0, s0
        mv      a1, s1
        addi    a2, sp, TPH_PKT_OFF
        call    packet_parse_header
        bnez    a0, .Ltph_invalid

        addi    a0, sp, TPH_CTX_OFF
        call    sha256_init

        lbu     t0, 0(s0)
        andi    t0, t0, 0x0f
        sb      t0, TPH_HEAD_OFF(sp)
        addi    a0, sp, TPH_CTX_OFF
        addi    a1, sp, TPH_HEAD_OFF
        li      a2, 1
        call    sha256_update

        lbu     t0, TPH_PKT_OFF + PKT_OFF_HEADER_TYPE(sp)
        bnez    t0, .Ltph_h2_hashable
        addi    s2, s0, 2
        addi    s3, s1, -2
        j       .Ltph_hash_tail

.Ltph_h2_hashable:
        addi    s2, s0, HASH_LEN + 2
        addi    s3, s1, -(HASH_LEN + 2)

.Ltph_hash_tail:
        addi    a0, sp, TPH_CTX_OFF
        mv      a1, s2
        mv      a2, s3
        call    sha256_update

        addi    a0, sp, TPH_CTX_OFF
        addi    a1, sp, TPH_DIGEST_OFF
        call    sha256_final

        la      s4, transport_packet_hashes
        la      t0, transport_packet_hash_count
        lw      s5, 0(t0)               /* valid hash count            */
        mv      s6, s5                  /* scan remaining              */
        mv      s7, s4                  /* current entry ptr           */

.Ltph_scan:
        beqz    s6, .Ltph_store
        mv      a0, s7
        addi    a1, sp, TPH_DIGEST_OFF
        li      a2, TRANSPORT_PACKET_HASH_SIZE
        call    .Ltph_memeq
        bnez    a0, .Ltph_duplicate
        addi    s7, s7, TRANSPORT_PACKET_HASH_SIZE
        addi    s6, s6, -1
        j       .Ltph_scan

.Ltph_store:
        la      t0, transport_packet_hash_next
        lw      s8, 0(t0)
        li      t1, TRANSPORT_PACKET_HASH_CAPACITY
        bltu    s8, t1, 1f
        mv      s8, zero
1:      slli    t2, s8, 4
        add     t2, s4, t2
        addi    t3, sp, TPH_DIGEST_OFF
        li      t4, TRANSPORT_PACKET_HASH_SIZE
2:      lbu     t5, 0(t3)
        sb      t5, 0(t2)
        addi    t3, t3, 1
        addi    t2, t2, 1
        addi    t4, t4, -1
        bnez    t4, 2b

        addi    s8, s8, 1
        li      t1, TRANSPORT_PACKET_HASH_CAPACITY
        bltu    s8, t1, 3f
        mv      s8, zero
3:      la      t0, transport_packet_hash_next
        sw      s8, 0(t0)

        li      t1, TRANSPORT_PACKET_HASH_CAPACITY
        bgeu    s5, t1, .Ltph_new
        addi    s5, s5, 1
        la      t0, transport_packet_hash_count
        sw      s5, 0(t0)

.Ltph_new:
        li      a0, TRANSPORT_OK
        j       .Ltph_return

.Ltph_duplicate:
        li      a0, TRANSPORT_STATUS_DUPLICATE
        j       .Ltph_return

.Ltph_invalid:
        li      a0, TRANSPORT_ERR_INVAL

.Ltph_return:
        lw      s0, TPH_S0_OFF(sp)
        lw      s1, TPH_S1_OFF(sp)
        lw      s2, TPH_S2_OFF(sp)
        lw      s3, TPH_S3_OFF(sp)
        lw      s4, TPH_S4_OFF(sp)
        lw      s5, TPH_S5_OFF(sp)
        lw      s6, TPH_S6_OFF(sp)
        lw      s7, TPH_S7_OFF(sp)
        lw      s8, TPH_S8_OFF(sp)
        lw      ra, TPH_RA_OFF(sp)
        addi    sp, sp, TPH_FRAME
        ret

.Ltph_memeq:
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

        .size   transport_packet_seen, . - transport_packet_seen
