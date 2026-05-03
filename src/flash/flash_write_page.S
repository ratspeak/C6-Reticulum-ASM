# ============================================================================
# @function:    flash_write_page
# @module:      flash
# @inputs:      a0 = offset within reserved identity flash region, a1 = src ptr, a2 = len
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0, a1, a2, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~24 + 14 per byte)
# @ct:          not-required
# @spec:        milestone-4 flash_write_page; qemu-virt page write with no 0->1 transitions
# @verify:      proofs/flash/flash_qemu_model.py
# @tests:       tests/flash/test_flash_driver.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Program bytes in the reserved qemu flash model. Validation is a full first
 * pass over the requested range so failed writes leave storage unchanged.
 */

        .include "flash.S"

        .section .text.flash_write_page, "ax", @progbits
        .global flash_write_page
        .type   flash_write_page, @function
flash_write_page:
        beqz    a2, .Lfwp_fail          /* zero-length writes rejected   */
        beqz    a1, .Lfwp_fail

        li      t0, FLASH_IDENTITY_REGION_SIZE
        bltu    t0, a0, .Lfwp_fail      /* offset > region size          */
        sub     t1, t0, a0              /* bytes available from offset   */
        bltu    t1, a2, .Lfwp_fail      /* len > available               */

        li      t0, FLASH_PAGE_SIZE - 1
        and     t1, a0, t0              /* offset within page            */
        li      t2, FLASH_PAGE_SIZE
        sub     t2, t2, t1              /* bytes left in this page       */
        bltu    t2, a2, .Lfwp_fail      /* write crosses page boundary   */

        la      t3, flash_model_region
        add     t3, t3, a0              /* dst cursor                    */
        mv      t4, a1                  /* src cursor                    */
        mv      t5, a2                  /* remaining                     */
1:      beqz    t5, 2f
        lbu     t0, 0(t3)               /* old byte                      */
        lbu     t1, 0(t4)               /* requested new byte            */
        and     t2, t0, t1
        bne     t2, t1, .Lfwp_fail      /* would set a 0 bit back to 1   */
        addi    t3, t3, 1
        addi    t4, t4, 1
        addi    t5, t5, -1
        j       1b

2:      la      t3, flash_model_region
        add     t3, t3, a0
        mv      t4, a1
        mv      t5, a2
3:      beqz    t5, .Lfwp_ok
        lbu     t6, 0(t4)
        sb      t6, 0(t3)
        addi    t3, t3, 1
        addi    t4, t4, 1
        addi    t5, t5, -1
        j       3b

.Lfwp_ok:
        li      a0, FLASH_OK
        ret

.Lfwp_fail:
        li      a0, FLASH_ERR_INVAL
        ret

        .size   flash_write_page, . - flash_write_page
