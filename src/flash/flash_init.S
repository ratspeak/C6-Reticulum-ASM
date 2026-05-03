# ============================================================================
# @function:    flash_init
# @module:      flash
# @inputs:      (none)
# @outputs:     a0 = 0 on success, negative errno on failure
# @clobbers:    a0, t0..t4
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (one 4096-byte erase on first qemu model init)
# @ct:          not-required
# @spec:        milestone-4 flash_init; qemu-virt reserved flash model initialization
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

        .size   flash_init, . - flash_init
