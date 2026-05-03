# ============================================================================
# @function:    flash_write_page
# @module:      flash
# @inputs:      a0 = offset within reserved identity flash region, a1 = src ptr, a2 = len
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0..a2, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       32
# @cycles:      bounded (~24 + 14 per byte on qemu; validate/read/write per byte on C6)
# @ct:          not-required
# @spec:        milestone-4 flash_write_page; qemu-virt model / TARGET_C6 ROM page write
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
        .ifdef TARGET_C6
        addi    sp, sp, -32
        sw      s0, 0(sp)
        sw      s1, 4(sp)
        sw      s2, 8(sp)
        sw      s3, 12(sp)
        sw      s4, 16(sp)
        sw      s5, 20(sp)
        sw      s6, 24(sp)
        sw      ra, 28(sp)

        beqz    a2, .Lfwp_c6_fail       /* zero-length writes rejected   */
        beqz    a1, .Lfwp_c6_fail

        li      t0, FLASH_IDENTITY_REGION_SIZE
        bltu    t0, a0, .Lfwp_c6_fail   /* offset > region size          */
        sub     t1, t0, a0
        bltu    t1, a2, .Lfwp_c6_fail   /* len > available               */

        li      t0, FLASH_PAGE_SIZE - 1
        and     t1, a0, t0              /* offset within page            */
        li      t2, FLASH_PAGE_SIZE
        sub     t2, t2, t1
        bltu    t2, a2, .Lfwp_c6_fail   /* write crosses page boundary   */

        li      t0, FLASH_C6_IDENTITY_ABS_OFFSET
        add     s4, t0, a0              /* absolute flash start          */
        mv      s5, a1                  /* original src                  */
        mv      s6, a2                  /* original len                  */
        la      s3, flash_c6_word_scratch

        mv      s0, s4                  /* validate cursor               */
        mv      s1, s5
        mv      s2, s6
1:      beqz    s2, 2f
        andi    t1, s0, 3
        sub     a0, s0, t1
        mv      a1, s3
        li      a2, 4
        li      t0, ESP_ROM_SPIFLASH_READ
        jalr    ra, 0(t0)
        bnez    a0, .Lfwp_c6_fail

        andi    t1, s0, 3
        add     t2, s3, t1
        lbu     t3, 0(t2)               /* old byte                      */
        lbu     t4, 0(s1)               /* requested new byte            */
        and     t5, t3, t4
        bne     t5, t4, .Lfwp_c6_fail
        addi    s0, s0, 1
        addi    s1, s1, 1
        addi    s2, s2, -1
        j       1b

2:      mv      s0, s4                  /* write cursor                  */
        mv      s1, s5
        mv      s2, s6
3:      beqz    s2, .Lfwp_c6_ok
        andi    t1, s0, 3
        sub     a0, s0, t1
        mv      a1, s3
        li      a2, 4
        li      t0, ESP_ROM_SPIFLASH_READ
        jalr    ra, 0(t0)
        bnez    a0, .Lfwp_c6_fail

        andi    t1, s0, 3
        add     t2, s3, t1
        lbu     t3, 0(s1)
        sb      t3, 0(t2)

        andi    t1, s0, 3
        sub     a0, s0, t1
        mv      a1, s3
        li      a2, 4
        li      t0, ESP_ROM_SPIFLASH_WRITE
        jalr    ra, 0(t0)
        bnez    a0, .Lfwp_c6_fail

        addi    s0, s0, 1
        addi    s1, s1, 1
        addi    s2, s2, -1
        j       3b

.Lfwp_c6_ok:
        li      a0, FLASH_OK
        j       .Lfwp_c6_return

.Lfwp_c6_fail:
        li      a0, FLASH_ERR_INVAL

.Lfwp_c6_return:
        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 20(sp)
        lw      s6, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret
        .else
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
        .endif

        .size   flash_write_page, . - flash_write_page
