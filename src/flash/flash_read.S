# ============================================================================
# @function:    flash_read
# @module:      flash
# @inputs:      a0 = offset within reserved identity flash region, a1 = out ptr, a2 = len
# @outputs:     a0 = 0 on success, negative errno on failure; out[0:len] filled on success
# @clobbers:    a0..a2, t0..t5
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       32
# @cycles:      bounded (~8 + 7 per byte on qemu; one ROM read per byte on C6)
# @ct:          not-required
# @spec:        milestone-4 flash_read; bounded qemu-virt model / TARGET_C6 ROM read
# @verify:      proofs/flash/flash_qemu_model.py
# @tests:       tests/flash/test_flash_driver.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Copy bytes out of the reserved qemu flash model. Zero-length reads are
 * accepted as no-ops, matching the milestone-4 driver contract.
 */

        .include "flash.S"

        .section .text.flash_read, "ax", @progbits
        .global flash_read
        .type   flash_read, @function
flash_read:
        .ifdef TARGET_C6
        addi    sp, sp, -32
        sw      s0, 0(sp)
        sw      s1, 4(sp)
        sw      s2, 8(sp)
        sw      s3, 12(sp)
        sw      ra, 28(sp)

        li      t0, FLASH_IDENTITY_REGION_SIZE
        bltu    t0, a0, .Lfr_c6_fail    /* offset > region size          */
        sub     t1, t0, a0
        bltu    t1, a2, .Lfr_c6_fail    /* len > available               */
        beqz    a2, .Lfr_c6_ok
        beqz    a1, .Lfr_c6_fail

        li      t0, FLASH_C6_IDENTITY_ABS_OFFSET
        add     s0, t0, a0              /* flash offset cursor           */
        mv      s1, a1                  /* dst cursor                    */
        mv      s2, a2                  /* remaining                     */
        la      s3, flash_c6_word_scratch

1:      beqz    s2, .Lfr_c6_ok
        andi    t1, s0, 3
        sub     a0, s0, t1              /* 4-byte aligned flash offset   */
        mv      a1, s3
        li      a2, 4
        li      t0, ESP_ROM_SPIFLASH_READ
        jalr    ra, 0(t0)
        bnez    a0, .Lfr_c6_fail

        andi    t1, s0, 3
        add     t2, s3, t1
        lbu     t3, 0(t2)
        sb      t3, 0(s1)
        addi    s0, s0, 1
        addi    s1, s1, 1
        addi    s2, s2, -1
        j       1b

.Lfr_c6_ok:
        li      a0, FLASH_OK
        j       .Lfr_c6_return

.Lfr_c6_fail:
        li      a0, FLASH_ERR_INVAL

.Lfr_c6_return:
        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret
        .else
        li      t0, FLASH_IDENTITY_REGION_SIZE
        bltu    t0, a0, .Lfr_fail       /* offset > region size          */
        sub     t1, t0, a0              /* bytes available from offset   */
        bltu    t1, a2, .Lfr_fail       /* len > available               */
        beqz    a2, .Lfr_ok
        beqz    a1, .Lfr_fail

        la      t2, flash_model_region
        add     t2, t2, a0              /* src cursor                    */
        mv      t3, a1                  /* dst cursor                    */
        mv      t4, a2                  /* remaining                     */
1:      beqz    t4, .Lfr_ok
        lbu     t5, 0(t2)
        sb      t5, 0(t3)
        addi    t2, t2, 1
        addi    t3, t3, 1
        addi    t4, t4, -1
        j       1b

.Lfr_ok:
        li      a0, FLASH_OK
        ret

.Lfr_fail:
        li      a0, FLASH_ERR_INVAL
        ret
        .endif

        .size   flash_read, . - flash_read
