# ============================================================================
# @function:    resource_part_parse
# @module:      resource
# @inputs:      a0 = part payload ptr, a1 = part payload len, a2 = random_hash ptr (4 bytes), a3 = resource_part_t* out
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       176
# @cycles:      bounded (~sha256 over 435 bytes + 4 byte copy)
# @ct:          required
# @spec:        milestone-7 resource_part_parse
# @verify:      proofs/resource/resource_part.py
# @tests:       tests/resource/test_resource_part_parse.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Parse one decrypted RESOURCE payload as raw part bytes and compute the
 * upstream resource map hash:
 *
 *     SHA256(part_payload || resource_random_hash)[0:4]
 *
 * Reticulum does not transmit an explicit RESOURCE part index. The receive
 * window later infers the position by matching this map hash against the
 * advertisement hashmap.
 */

        .include "resource.S"
        .include "sha256.S"

        .equ RPP_CTX_OFF,     0
        .equ RPP_DIGEST_OFF,  112
        .equ RPP_S0_OFF,      144
        .equ RPP_S1_OFF,      148
        .equ RPP_S2_OFF,      152
        .equ RPP_S3_OFF,      156
        .equ RPP_RA_OFF,      172
        .equ RPP_FRAME,       176

        .section .text.resource_part_parse, "ax", @progbits
        .global resource_part_parse
        .type   resource_part_parse, @function
resource_part_parse:
        addi    sp, sp, -RPP_FRAME
        sw      s0, RPP_S0_OFF(sp)
        sw      s1, RPP_S1_OFF(sp)
        sw      s2, RPP_S2_OFF(sp)
        sw      s3, RPP_S3_OFF(sp)
        sw      ra, RPP_RA_OFF(sp)

        mv      s0, a0                  /* part payload ptr             */
        mv      s1, a1                  /* part payload len             */
        mv      s2, a2                  /* resource random_hash ptr     */
        mv      s3, a3                  /* resource_part_t out          */

        beqz    s2, .Lrpp_invalid
        beqz    s3, .Lrpp_invalid
        beqz    s1, .Lrpp_len_ok
        beqz    s0, .Lrpp_invalid
.Lrpp_len_ok:
        li      t0, RESOURCE_PART_MAX_LEN
        bltu    t0, s1, .Lrpp_overflow

        sw      s1, RESOURCE_PART_OFF_PAYLOAD_LEN(s3)
        sw      s0, RESOURCE_PART_OFF_PAYLOAD_PTR(s3)

        mv      a0, sp
        call    sha256_init

        beqz    s1, .Lrpp_random_hash
        mv      a0, sp
        mv      a1, s0
        mv      a2, s1
        call    sha256_update

.Lrpp_random_hash:
        mv      a0, sp
        mv      a1, s2
        li      a2, RESOURCE_RANDOM_HASH_SIZE
        call    sha256_update

        mv      a0, sp
        addi    a1, sp, RPP_DIGEST_OFF
        call    sha256_final

        addi    t0, sp, RPP_DIGEST_OFF
        addi    t1, s3, RESOURCE_PART_OFF_MAPHASH
        li      t2, RESOURCE_MAPHASH_SIZE
.Lrpp_copy_maphash:
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, .Lrpp_copy_maphash

        li      a0, RESOURCE_OK
        j       .Lrpp_done

.Lrpp_invalid:
        li      a0, RESOURCE_ERR_INVAL
        j       .Lrpp_done

.Lrpp_overflow:
        li      a0, RESOURCE_ERR_OVERFLOW

.Lrpp_done:
        lw      s0, RPP_S0_OFF(sp)
        lw      s1, RPP_S1_OFF(sp)
        lw      s2, RPP_S2_OFF(sp)
        lw      s3, RPP_S3_OFF(sp)
        lw      ra, RPP_RA_OFF(sp)
        addi    sp, sp, RPP_FRAME
        ret

        .size   resource_part_parse, . - resource_part_parse
