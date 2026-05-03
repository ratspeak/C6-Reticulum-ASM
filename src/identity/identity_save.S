# ============================================================================
# @function:    identity_save
# @module:      identity
# @inputs:      a0 = identity_t* identity
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s3
# @stack:       32
# @cycles:      bounded (hash validation + 256-byte record write/readback)
# @ct:          not-required
# @spec:        milestone-4 identity_save; durable 256-byte identity record
# @verify:      proofs/identity/identity_persistence.py
# @tests:       tests/identity/test_identity_persistence.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Save a Reticulum identity into the reserved flash identity sector.
 *
 * The record is assembled in static scratch, checksummed as
 * SHA256(record[0..15] || identity_t), then written as one page after a
 * sector erase. A full 256-byte readback must match before success returns.
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

        .section .text.identity_save, "ax", @progbits
        .global identity_save
        .type   identity_save, @function
identity_save:
        addi    sp, sp, -FRAME
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      ra, RA_OFF(sp)

        beqz    a0, .Lis_inval
        mv      s0, a0                  /* identity ptr                 */
        la      s1, identity_record_buf
        la      s2, identity_verify_buf
        la      s3, identity_hash_buf

        /* Validate identity.hash before writing private key material. */
        addi    a0, s0, IDENTITY_OFF_X25519_PK
        mv      a1, s3
        call    identity_hash
        addi    t0, s0, IDENTITY_OFF_HASH
        mv      t1, s3
        li      t2, IDENTITY_HASH_SIZE
.Lis_hash_cmp:
        beqz    t2, .Lis_build_record
        lbu     t3, 0(t0)
        lbu     t4, 0(t1)
        bne     t3, t4, .Lis_inval
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lis_hash_cmp

.Lis_build_record:
        /* Start with erased padding, then overwrite header/identity/checksum. */
        mv      t0, s1
        li      t1, IDENTITY_RECORD_SIZE
        li      t2, 0xff
.Lis_fill_ff:
        beqz    t1, .Lis_header
        sb      t2, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       .Lis_fill_ff

.Lis_header:
        li      t0, IDENTITY_RECORD_MAGIC
        sw      t0, IDENTITY_RECORD_OFF_MAGIC(s1)
        li      t0, IDENTITY_RECORD_VERSION
        sb      t0, IDENTITY_RECORD_OFF_VERSION(s1)
        li      t0, IDENTITY_RECORD_FLAGS
        sb      t0, IDENTITY_RECORD_OFF_FLAGS(s1)
        li      t0, IDENTITY_RECORD_HEADER_LEN
        sh      t0, IDENTITY_RECORD_OFF_HEADER_LEN(s1)
        li      t0, IDENTITY_T_SIZE
        sw      t0, IDENTITY_RECORD_OFF_IDENTITY_LEN(s1)
        sw      zero, IDENTITY_RECORD_OFF_RESERVED(s1)

        mv      t0, s0
        addi    t1, s1, IDENTITY_RECORD_OFF_IDENTITY
        li      t2, IDENTITY_T_SIZE
.Lis_copy_identity:
        beqz    t2, .Lis_checksum
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lis_copy_identity

.Lis_checksum:
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
        addi    a1, s1, IDENTITY_RECORD_OFF_CHECKSUM
        call    sha256_final

        li      a0, FLASH_IDENTITY_RECORD_OFFSET
        call    flash_erase_sector
        bnez    a0, .Lis_io

        li      a0, FLASH_IDENTITY_RECORD_OFFSET
        mv      a1, s1
        li      a2, IDENTITY_RECORD_SIZE
        call    flash_write_page
        bnez    a0, .Lis_io

        li      a0, FLASH_IDENTITY_RECORD_OFFSET
        mv      a1, s2
        li      a2, IDENTITY_RECORD_SIZE
        call    flash_read
        bnez    a0, .Lis_io

        mv      t0, s1
        mv      t1, s2
        li      t2, IDENTITY_RECORD_SIZE
.Lis_readback_cmp:
        beqz    t2, .Lis_ok
        lbu     t3, 0(t0)
        lbu     t4, 0(t1)
        bne     t3, t4, .Lis_inval
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lis_readback_cmp

.Lis_ok:
        li      a0, IDENTITY_OK
        j       .Lis_ret
.Lis_inval:
        li      a0, IDENTITY_ERR_INVAL
        j       .Lis_ret
.Lis_io:
        li      a0, IDENTITY_ERR_IO
.Lis_ret:
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   identity_save, . - identity_save
