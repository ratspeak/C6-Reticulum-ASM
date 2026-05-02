# ============================================================================
# @function:    clock_init
# @module:      clock
# @inputs:      (none)
# @outputs:     (target's CPU clock at the documented operating frequency)
# @clobbers:    (none on qemu-virt; t0..t6 reserved on C6)
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (target-dependent; ~1 on qemu, ~tens of thousands on C6 PLL lock)
# @ct:          not-required
# @spec:        ESP32-C6 TRM Chapter 6 (Clock Tree); milestone-1 §clock
# @verify:      kat-only; clock setup has no externally observable contract beyond "ret"
# @tests:       tests/clock/test_clock_init.py
# @adrs:        0008
# @status:      verified
# ============================================================================

/* On qemu-virt the CPU runs at qemu's configured rate; nothing to do.
 * On the real ESP32-C6 we will:
 *   1. Switch CPU clock source to XTAL (40 MHz) temporarily.
 *   2. Configure PLL multipliers (TRM §6.2.4).
 *   3. Wait for PLL lock.
 *   4. Switch CPU clock source to PLL output.
 *   5. Set bus clock dividers.
 * That sequence ships with the C6 bring-up; the qemu-virt build keeps
 * this function a single `ret` so the boot chain can be assembled and
 * tested end-to-end before the hardware register dance is written.
 */

        .section .text.clock_init, "ax", @progbits
        .global clock_init
        .type   clock_init, @function
clock_init:
        .ifdef TARGET_QEMU_VIRT
        ret
        .endif
        .ifdef TARGET_C6
        .error "clock_init for TARGET_C6 not implemented yet"
        .endif

        .size   clock_init, . - clock_init
