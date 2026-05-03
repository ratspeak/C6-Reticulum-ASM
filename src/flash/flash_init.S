# ============================================================================
# @function:    flash_init
# @module:      flash
# @inputs:      (none)
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a5, t0..t4
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       16
# @cycles:      bounded (one 4096-byte model init on qemu; two ROM calls on C6)
# @ct:          not-required
# @spec:        milestone-4 flash_init; qemu-virt model / TARGET_C6 reserved flash validation
# @verify:      proofs/flash/flash_qemu_model.py
# @tests:       tests/flash/test_flash_driver.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Initialize the qemu-virt flash model exactly once. The backing storage is
 * BSS, so reset starts as zeroed RAM; flash_init converts it to the erased
 * value 0xff and sets a persistent in-process flag. Later calls are no-ops so
 * identity persistence code can call flash_init defensively without erasing
 * existing model contents.
 */

        .include "flash.S"

        .section .text.flash_init, "ax", @progbits
        .global flash_init
        .type   flash_init, @function
flash_init:
        .ifdef TARGET_C6
        li      t0, FLASH_SECTOR_SIZE - 1
        li      t1, FLASH_C6_IDENTITY_ABS_OFFSET
        and     t2, t1, t0
        bnez    t2, .Lfi_c6_fail
        li      t1, FLASH_IDENTITY_REGION_SIZE
        and     t2, t1, t0
        bnez    t2, .Lfi_c6_fail
        li      t1, FLASH_C6_IDENTITY_ABS_OFFSET + FLASH_IDENTITY_REGION_SIZE
        li      t2, FLASH_C6_CHIP_SIZE
        bne     t1, t2, .Lfi_c6_fail

        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      a0, 0                   /* device ID not used by us      */
        li      a1, FLASH_C6_CHIP_SIZE
        li      a2, FLASH_C6_BLOCK_SIZE
        li      a3, FLASH_SECTOR_SIZE
        li      a4, FLASH_PAGE_SIZE
        li      a5, FLASH_C6_STATUS_MASK
        li      t0, ESP_ROM_SPIFLASH_CONFIG_PARAM
        jalr    ra, 0(t0)
        bnez    a0, .Lfi_c6_restore_fail

        li      a0, FLASH_C6_CHIP_SIZE - 4
        la      a1, flash_c6_word_scratch
        li      a2, 4
        li      t0, ESP_ROM_SPIFLASH_READ
        jalr    ra, 0(t0)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        bnez    a0, .Lfi_c6_fail

        li      a0, FLASH_OK
        ret

.Lfi_c6_fail:
        li      a0, FLASH_ERR_INVAL
        ret

.Lfi_c6_restore_fail:
        lw      ra, 12(sp)
        addi    sp, sp, 16
        j       .Lfi_c6_fail
        .else
        la      t0, flash_model_initialized
        lw      t1, 0(t0)
        bnez    t1, .Lfi_ok

        la      t2, flash_model_region
        li      t3, FLASH_IDENTITY_REGION_SIZE
        li      t4, 0xff
1:      beqz    t3, 2f
        sb      t4, 0(t2)
        addi    t2, t2, 1
        addi    t3, t3, -1
        j       1b

2:      li      t1, 1
        sw      t1, 0(t0)

.Lfi_ok:
        li      a0, FLASH_OK
        ret
        .endif

        .size   flash_init, . - flash_init
