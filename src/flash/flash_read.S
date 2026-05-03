# ============================================================================
# @function:    flash_read
# @module:      flash
# @inputs:      a0 = offset within reserved identity flash region, a1 = out ptr, a2 = len
# @outputs:     a0 = 0 on success, negative errno on failure; out[0:len] filled on success
# @clobbers:    a0, a1, a2, t0..t5
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~8 + 7 per byte)
# @ct:          not-required
# @spec:        milestone-4 flash_read; bounded qemu-virt flash model read
# @verify:      kat-only; qemu model coverage in tests/flash/test_flash_driver.py
# @tests:       tests/flash/test_flash_driver.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      tested
# ============================================================================

/* Copy bytes out of the reserved qemu flash model. Zero-length reads are
 * accepted as no-ops, matching the milestone-4 driver contract.
 */

        .include "flash.S"

        .section .text.flash_read, "ax", @progbits
        .global flash_read
        .type   flash_read, @function
flash_read:
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

        .size   flash_read, . - flash_read
