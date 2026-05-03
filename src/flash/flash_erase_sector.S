# ============================================================================
# @function:    flash_erase_sector
# @module:      flash
# @inputs:      a0 = sector offset within reserved identity flash region
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0, t0..t5
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       16
# @cycles:      bounded (4096 byte stores on qemu; one ROM sector erase on C6)
# @ct:          not-required
# @spec:        milestone-4 flash_erase_sector; qemu-virt model / TARGET_C6 ROM sector erase
# @verify:      proofs/flash/flash_qemu_model.py
# @tests:       tests/flash/test_flash_driver.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Erase one sector in the reserved qemu flash model. Milestone 4 reserves one
 * sector, so the only valid sector offset today is 0.
 */

        .include "flash.S"

        .section .text.flash_erase_sector, "ax", @progbits
        .global flash_erase_sector
        .type   flash_erase_sector, @function
flash_erase_sector:
        .ifdef TARGET_C6
        li      t0, FLASH_SECTOR_SIZE - 1
        and     t1, a0, t0
        bnez    t1, .Lfes_c6_fail       /* unaligned sector offset       */

        li      t0, FLASH_IDENTITY_REGION_SIZE
        bgeu    a0, t0, .Lfes_c6_fail   /* offset outside region         */
        li      t1, FLASH_SECTOR_SIZE
        sub     t2, t0, a0
        bltu    t2, t1, .Lfes_c6_fail   /* full sector must fit          */

        li      t3, FLASH_C6_IDENTITY_ABS_OFFSET
        add     t3, t3, a0
        srli    a0, t3, 12              /* ROM takes a sector number     */

        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      t0, ESP_ROM_SPIFLASH_ERASE_SECTOR
        jalr    ra, 0(t0)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        bnez    a0, .Lfes_c6_fail

        li      a0, FLASH_OK
        ret

.Lfes_c6_fail:
        li      a0, FLASH_ERR_INVAL
        ret
        .else
        li      t0, FLASH_SECTOR_SIZE - 1
        and     t1, a0, t0
        bnez    t1, .Lfes_fail          /* unaligned sector offset       */

        li      t0, FLASH_IDENTITY_REGION_SIZE
        bgeu    a0, t0, .Lfes_fail      /* offset outside region         */
        li      t1, FLASH_SECTOR_SIZE
        sub     t2, t0, a0
        bltu    t2, t1, .Lfes_fail      /* full sector must fit          */

        la      t3, flash_model_region
        add     t3, t3, a0
        li      t4, FLASH_SECTOR_SIZE
        li      t5, 0xff
1:      beqz    t4, .Lfes_ok
        sb      t5, 0(t3)
        addi    t3, t3, 1
        addi    t4, t4, -1
        j       1b

.Lfes_ok:
        li      a0, FLASH_OK
        ret

.Lfes_fail:
        li      a0, FLASH_ERR_INVAL
        ret
        .endif

        .size   flash_erase_sector, . - flash_erase_sector
