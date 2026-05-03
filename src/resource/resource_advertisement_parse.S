# ============================================================================
# @function:    resource_advertisement_parse
# @module:      resource
# @inputs:      a0 = msgpack advertisement ptr, a1 = advertisement len, a2 = resource_advertisement_t* out
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       64
# @cycles:      bounded (~431-byte msgpack scan)
# @ct:          not-required
# @spec:        milestone-7 resource_advertisement_parse
# @verify:      proofs/resource/resource_advertisement.py
# @tests:       tests/resource/test_resource_advertisement_parse.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Strict subset parser for upstream ResourceAdvertisement.pack().
 *
 * Accepted msgpack shape:
 *   {"t","d","n","h","r","o","i","l","q","f","m"} in pack() order
 *
 * The milestone subset accepts only encrypted, single-segment,
 * non-request/non-response advertisements:
 *   q == nil, f == RESOURCE_ADV_FLAGS_ENCRYPTED, i == 1, l == 1
 */

        .include "resource.S"

        .equ RAP_S0_OFF,   0
        .equ RAP_S1_OFF,   4
        .equ RAP_S2_OFF,   8
        .equ RAP_S3_OFF,   12
        .equ RAP_S4_OFF,   16
        .equ RAP_S5_OFF,   20
        .equ RAP_S6_OFF,   24
        .equ RAP_S7_OFF,   28
        .equ RAP_S8_OFF,   32
        .equ RAP_S9_OFF,   36
        .equ RAP_S10_OFF,  40
        .equ RAP_S11_OFF,  44
        .equ RAP_RA_OFF,   60
        .equ RAP_FRAME,    64

        .section .text.resource_advertisement_parse, "ax", @progbits
        .global resource_advertisement_parse
        .type   resource_advertisement_parse, @function
resource_advertisement_parse:
        addi    sp, sp, -RAP_FRAME
        sw      s0, RAP_S0_OFF(sp)
        sw      s1, RAP_S1_OFF(sp)
        sw      s2, RAP_S2_OFF(sp)
        sw      s3, RAP_S3_OFF(sp)
        sw      s4, RAP_S4_OFF(sp)
        sw      s5, RAP_S5_OFF(sp)
        sw      s6, RAP_S6_OFF(sp)
        sw      s7, RAP_S7_OFF(sp)
        sw      s8, RAP_S8_OFF(sp)
        sw      s9, RAP_S9_OFF(sp)
        sw      s10, RAP_S10_OFF(sp)
        sw      s11, RAP_S11_OFF(sp)
        sw      ra, RAP_RA_OFF(sp)

        mv      s0, a0                  /* raw advertisement ptr        */
        mv      s1, a1                  /* raw advertisement len        */
        mv      s2, a2                  /* out struct                   */

        beqz    s0, .Lrap_invalid
        beqz    s2, .Lrap_invalid
        li      t0, RESOURCE_ADV_MAX_RAW_LEN
        bltu    t0, s1, .Lrap_invalid

        mv      s3, s0                  /* cursor                       */
        add     s4, s0, s1              /* end                          */

        call    .Lrap_read_byte
        bltz    a0, .Lrap_invalid
        li      t0, 0x80 | RESOURCE_ADV_MSGPACK_FIELDS
        bne     a0, t0, .Lrap_invalid

        li      a0, 0x74                /* "t": transfer size          */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s5, a0
        sw      s5, RESOURCE_ADV_OFF_TRANSFER_SIZE(s2)

        li      a0, 0x64                /* "d": uncompressed data size */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s6, a0
        sw      s6, RESOURCE_ADV_OFF_DATA_SIZE(s2)

        li      a0, 0x6e                /* "n": part count             */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s7, a0
        sw      s7, RESOURCE_ADV_OFF_PART_COUNT(s2)

        li      a0, 0x68                /* "h": resource hash          */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_bin
        beqz    a0, .Lrap_invalid
        li      t0, RESOURCE_HASH_SIZE
        bne     a1, t0, .Lrap_invalid
        addi    a1, s2, RESOURCE_ADV_OFF_RESOURCE_HASH
        li      a2, RESOURCE_HASH_SIZE
        call    .Lrap_copy_bytes

        li      a0, 0x72                /* "r": resource random hash   */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_bin
        beqz    a0, .Lrap_invalid
        li      t0, RESOURCE_RANDOM_HASH_SIZE
        bne     a1, t0, .Lrap_invalid
        addi    a1, s2, RESOURCE_ADV_OFF_RANDOM_HASH
        li      a2, RESOURCE_RANDOM_HASH_SIZE
        call    .Lrap_copy_bytes

        li      a0, 0x6f                /* "o": original hash          */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_bin
        beqz    a0, .Lrap_invalid
        li      t0, RESOURCE_HASH_SIZE
        bne     a1, t0, .Lrap_invalid
        addi    a1, s2, RESOURCE_ADV_OFF_ORIGINAL_HASH
        li      a2, RESOURCE_HASH_SIZE
        call    .Lrap_copy_bytes

        li      a0, 0x69                /* "i": segment index          */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s9, a0
        sw      s9, RESOURCE_ADV_OFF_SEGMENT_INDEX(s2)

        li      a0, 0x6c                /* "l": total segments         */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s10, a0
        sw      s10, RESOURCE_ADV_OFF_TOTAL_SEGMENTS(s2)

        li      a0, 0x71                /* "q": request id             */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_expect_nil
        bltz    a0, .Lrap_invalid

        li      a0, 0x66                /* "f": flags                  */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_uint
        bltz    a0, .Lrap_invalid
        mv      s8, a0
        sw      s8, RESOURCE_ADV_OFF_FLAGS(s2)

        li      a0, 0x6d                /* "m": hashmap bytes          */
        call    .Lrap_expect_key
        bltz    a0, .Lrap_invalid
        call    .Lrap_parse_bin
        beqz    a0, .Lrap_invalid
        mv      s11, a1
        sw      s11, RESOURCE_ADV_OFF_HASHMAP_LEN(s2)
        sw      a0, RESOURCE_ADV_OFF_HASHMAP_PTR(s2)

        bne     s3, s4, .Lrap_invalid

        beqz    s5, .Lrap_invalid
        beqz    s6, .Lrap_invalid
        beqz    s7, .Lrap_invalid
        li      t0, RESOURCE_ADV_MAX_PARTS
        bltu    t0, s7, .Lrap_invalid

        li      t0, RESOURCE_ADV_FLAGS_ENCRYPTED
        bne     s8, t0, .Lrap_invalid
        li      t0, 1
        bne     s9, t0, .Lrap_invalid
        bne     s10, t0, .Lrap_invalid

        slli    t0, s7, 2
        bne     s11, t0, .Lrap_invalid
        li      t1, RESOURCE_PART_MAX_LEN
        mul     t2, s7, t1
        bltu    t2, s5, .Lrap_invalid
        addi    t3, s7, -1
        mul     t3, t3, t1
        addi    t3, t3, 1
        bltu    s5, t3, .Lrap_invalid
        bltu    s5, s6, .Lrap_invalid

        addi    a0, s2, RESOURCE_ADV_OFF_RESOURCE_HASH
        addi    a1, s2, RESOURCE_ADV_OFF_ORIGINAL_HASH
        li      a2, RESOURCE_HASH_SIZE
        call    .Lrap_memeq
        beqz    a0, .Lrap_invalid

        sw      s1, RESOURCE_ADV_OFF_RAW_LEN(s2)
        li      a0, RESOURCE_OK
        j       .Lrap_done

.Lrap_invalid:
        li      a0, RESOURCE_ERR_INVAL

.Lrap_done:
        lw      s0, RAP_S0_OFF(sp)
        lw      s1, RAP_S1_OFF(sp)
        lw      s2, RAP_S2_OFF(sp)
        lw      s3, RAP_S3_OFF(sp)
        lw      s4, RAP_S4_OFF(sp)
        lw      s5, RAP_S5_OFF(sp)
        lw      s6, RAP_S6_OFF(sp)
        lw      s7, RAP_S7_OFF(sp)
        lw      s8, RAP_S8_OFF(sp)
        lw      s9, RAP_S9_OFF(sp)
        lw      s10, RAP_S10_OFF(sp)
        lw      s11, RAP_S11_OFF(sp)
        lw      ra, RAP_RA_OFF(sp)
        addi    sp, sp, RAP_FRAME
        ret

.Lrap_read_byte:
        bgeu    s3, s4, .Lrap_read_fail
        lbu     a0, 0(s3)
        addi    s3, s3, 1
        ret
.Lrap_read_fail:
        li      a0, RESOURCE_ERR_INVAL
        ret

.Lrap_expect_key:
        mv      t5, ra
        mv      t6, a0
        call    .Lrap_read_byte
        bltz    a0, .Lrap_expect_fail
        li      t0, 0xa1
        bne     a0, t0, .Lrap_expect_fail
        call    .Lrap_read_byte
        bltz    a0, .Lrap_expect_fail
        bne     a0, t6, .Lrap_expect_fail
        li      a0, RESOURCE_OK
        jr      t5
.Lrap_expect_fail:
        li      a0, RESOURCE_ERR_INVAL
        jr      t5

.Lrap_expect_nil:
        mv      t5, ra
        call    .Lrap_read_byte
        bltz    a0, .Lrap_expect_nil_fail
        li      t0, 0xc0
        bne     a0, t0, .Lrap_expect_nil_fail
        li      a0, RESOURCE_OK
        jr      t5
.Lrap_expect_nil_fail:
        li      a0, RESOURCE_ERR_INVAL
        jr      t5

.Lrap_parse_uint:
        mv      t5, ra
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        li      t0, 0x80
        bltu    a0, t0, .Lrap_uint_done
        li      t0, 0xcc
        beq     a0, t0, .Lrap_uint8
        li      t0, 0xcd
        beq     a0, t0, .Lrap_uint16
        li      t0, 0xce
        beq     a0, t0, .Lrap_uint32
        j       .Lrap_uint_fail

.Lrap_uint8:
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        jr      t5

.Lrap_uint16:
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        slli    t1, a0, 8
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        or      a0, t1, a0
        jr      t5

.Lrap_uint32:
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        slli    t1, a0, 24
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        slli    t2, a0, 16
        or      t1, t1, t2
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        slli    t2, a0, 8
        or      t1, t1, t2
        call    .Lrap_read_byte
        bltz    a0, .Lrap_uint_fail
        or      a0, t1, a0
        jr      t5

.Lrap_uint_done:
        jr      t5
.Lrap_uint_fail:
        li      a0, RESOURCE_ERR_INVAL
        jr      t5

.Lrap_parse_bin:
        mv      t5, ra
        call    .Lrap_read_byte
        bltz    a0, .Lrap_bin_fail
        li      t0, 0xc4
        beq     a0, t0, .Lrap_bin8
        li      t0, 0xc5
        beq     a0, t0, .Lrap_bin16
        j       .Lrap_bin_fail

.Lrap_bin8:
        call    .Lrap_read_byte
        bltz    a0, .Lrap_bin_fail
        mv      t2, a0
        j       .Lrap_bin_len_ready

.Lrap_bin16:
        call    .Lrap_read_byte
        bltz    a0, .Lrap_bin_fail
        slli    t2, a0, 8
        call    .Lrap_read_byte
        bltz    a0, .Lrap_bin_fail
        or      t2, t2, a0

.Lrap_bin_len_ready:
        sub     t3, s4, s3
        bltu    t3, t2, .Lrap_bin_fail
        mv      a0, s3
        mv      a1, t2
        add     s3, s3, t2
        jr      t5
.Lrap_bin_fail:
        li      a0, 0
        li      a1, 0
        jr      t5

.Lrap_copy_bytes:
        beqz    a2, .Lrap_copy_done
        lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       .Lrap_copy_bytes
.Lrap_copy_done:
        ret

.Lrap_memeq:
        li      t0, 1
.Lrap_memeq_loop:
        beqz    a2, .Lrap_memeq_done
        lbu     t1, 0(a0)
        lbu     t2, 0(a1)
        beq     t1, t2, .Lrap_memeq_next
        li      t0, 0
.Lrap_memeq_next:
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       .Lrap_memeq_loop
.Lrap_memeq_done:
        mv      a0, t0
        ret

        .size   resource_advertisement_parse, . - resource_advertisement_parse
