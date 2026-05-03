# ============================================================================
# @function:    identity_load
# @module:      identity
# @inputs:      a0 = identity_t* out
# @outputs:     a0 = 0 on success, negative errno on failure or missing identity
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       32
# @cycles:      bounded (256-byte record read + checksum/hash validation)
# @ct:          not-required
# @spec:        milestone-4 identity_load; durable 256-byte identity record
# @verify:      proofs/identity/identity_persistence.py
# @tests:       tests/identity/test_identity_persistence.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Load and validate the milestone-4 identity record before copying identity_t
 * to the caller. Malformed records never partially update the output buffer.
 */

        .include "identity.S"
        .include "flash.S"
        .include "sha256.S"

        .equ FRAME,  32
        .equ S0_OFF, 0
        .equ S1_OFF, 4
        .equ S2_OFF, 8
        .equ S3_OFF, 12
        .equ RA_OFF, 28

        .section .text.identity_load, "ax", @progbits
        .global identity_load
        .type   identity_load, @function
identity_load:
        addi    sp, sp, -FRAME
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      ra, RA_OFF(sp)

        beqz    a0, .Lil_inval
        mv      s0, a0                  /* output identity_t ptr        */
        la      s1, identity_record_buf
        la      s2, identity_hash_buf
        la      s3, sha256_digest_buf

        li      a0, FLASH_IDENTITY_RECORD_OFFSET
        mv      a1, s1
        li      a2, IDENTITY_RECORD_SIZE
        call    flash_read
        bnez    a0, .Lil_io

        /* All-erased sector means no stored identity. */
        mv      t0, s1
        li      t1, IDENTITY_RECORD_SIZE
        li      t2, 0xff
.Lil_erased_scan:
        beqz    t1, .Lil_missing
        lbu     t3, 0(t0)
        bne     t3, t2, .Lil_check_header
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       .Lil_erased_scan

.Lil_check_header:
        lw      t0, IDENTITY_RECORD_OFF_MAGIC(s1)
        li      t1, IDENTITY_RECORD_MAGIC
        bne     t0, t1, .Lil_inval
        lbu     t0, IDENTITY_RECORD_OFF_VERSION(s1)
        li      t1, IDENTITY_RECORD_VERSION
        bne     t0, t1, .Lil_inval
        lbu     t0, IDENTITY_RECORD_OFF_FLAGS(s1)
        li      t1, IDENTITY_RECORD_FLAGS
        bne     t0, t1, .Lil_inval
        lhu     t0, IDENTITY_RECORD_OFF_HEADER_LEN(s1)
        li      t1, IDENTITY_RECORD_HEADER_LEN
        bne     t0, t1, .Lil_inval
        lw      t0, IDENTITY_RECORD_OFF_IDENTITY_LEN(s1)
        li      t1, IDENTITY_T_SIZE
        bne     t0, t1, .Lil_inval
        lw      t0, IDENTITY_RECORD_OFF_RESERVED(s1)
        bnez    t0, .Lil_inval

        addi    t0, s1, IDENTITY_RECORD_OFF_PADDING
        li      t1, IDENTITY_RECORD_PADDING_SIZE
        li      t2, 0xff
.Lil_padding_scan:
        beqz    t1, .Lil_checksum
        lbu     t3, 0(t0)
        bne     t3, t2, .Lil_inval
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       .Lil_padding_scan

.Lil_checksum:
        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        mv      a1, s1
        li      a2, IDENTITY_RECORD_OFF_CHECKSUM
        call    sha256_update
        la      a0, sha256_ctx
        addi    a1, s1, IDENTITY_RECORD_OFF_IDENTITY
        li      a2, IDENTITY_T_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        mv      a1, s3
        call    sha256_final

        mv      t0, s3
        addi    t1, s1, IDENTITY_RECORD_OFF_CHECKSUM
        li      t2, IDENTITY_RECORD_CHECKSUM_SIZE
.Lil_checksum_cmp:
        beqz    t2, .Lil_identity_hash
        lbu     t3, 0(t0)
        lbu     t4, 0(t1)
        bne     t3, t4, .Lil_inval
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lil_checksum_cmp

.Lil_identity_hash:
        addi    a0, s1, IDENTITY_RECORD_OFF_IDENTITY + IDENTITY_OFF_X25519_PK
        mv      a1, s2
        call    identity_hash
        mv      t0, s2
        addi    t1, s1, IDENTITY_RECORD_OFF_IDENTITY + IDENTITY_OFF_HASH
        li      t2, IDENTITY_HASH_SIZE
.Lil_hash_cmp:
        beqz    t2, .Lil_copy_to_out
        lbu     t3, 0(t0)
        lbu     t4, 0(t1)
        bne     t3, t4, .Lil_inval
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lil_hash_cmp

.Lil_copy_to_out:
        addi    t0, s1, IDENTITY_RECORD_OFF_IDENTITY
        mv      t1, s0
        li      t2, IDENTITY_T_SIZE
.Lil_copy_identity:
        beqz    t2, .Lil_ok
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lil_copy_identity

.Lil_ok:
        li      a0, IDENTITY_OK
        j       .Lil_ret
.Lil_missing:
        li      a0, IDENTITY_ERR_MISSING
        j       .Lil_ret
.Lil_inval:
        li      a0, IDENTITY_ERR_INVAL
        j       .Lil_ret
.Lil_io:
        li      a0, IDENTITY_ERR_IO
.Lil_ret:
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   identity_load, . - identity_load
