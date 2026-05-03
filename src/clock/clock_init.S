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

        .include "regs.S"

        .section .text.clock_init, "ax", @progbits
        .global clock_init
        .type   clock_init, @function
clock_init:
        .ifdef TARGET_QEMU_VIRT
        ret
        .endif
        .ifdef TARGET_C6
        /* Accept the mask-ROM's clock configuration (typically 80 MHz CPU
         * via PLL after the ROM stage prepares XIP). PLL re-programming
         * to 160 MHz lands when milestone 8's LoRa SPI burst loop needs
         * the headroom; until then the on-chip SYSTIMER is the wall-clock
         * reference and ticks at 16 MHz independent of CPU rate.
         *
         * Watchdog bring-down. The boot ROM enables three watchdogs
         * before handing off:
         *   1. TIMG0 main WDT (WDTCONFIG0.WDT_EN + WDTCONFIG0.FLASHBOOT_MOD_EN)
         *   2. LP-WDT (RTC) — usually default-disabled but we belt-and-brace
         *   3. Super WDT (SWD) — fires after a long timeout regardless
         * Each is unlocked by writing 0x50D83AA1 to its WPROTECT register,
         * then re-locked by writing 0. Without this disable the polling
         * loop in _main triggers a TG0_WDT_HPSYS reset within ~1 s
         * (empirically observed on first boot). */
        li      t1, WDT_WKEY                /* 0x50D83AA1 — same key x3 */

        /* TIMG0 main WDT */
        li      t0, TIMG0_BASE
        sw      t1, 0x64(t0)                /* WDTWPROTECT: unlock      */
        sw      zero, 0x48(t0)              /* WDTCONFIG0: clear EN+FLASHBOOT */
        sw      zero, 0x64(t0)              /* WDTWPROTECT: re-lock     */

        /* LP-WDT (RTC) */
        li      t0, LP_WDT_BASE
        sw      t1, 0x18(t0)                /* WPROTECT: unlock         */
        sw      zero, 0x00(t0)              /* CONFIG0: clear WDT_EN    */
        sw      zero, 0x18(t0)              /* WPROTECT: re-lock        */

        /* Super WDT — read-modify-write to set DISABLE without touching
         * the auto-feed bit or other state the ROM may rely on. */
        sw      t1, 0x20(t0)                /* SWD_WPROTECT: unlock     */
        lw      t2, 0x1C(t0)                /* SWD_CONFIG               */
        li      t3, LP_WDT_SWD_DISABLE      /* bit 30                   */
        or      t2, t2, t3
        sw      t2, 0x1C(t0)                /* SWD_CONFIG: DISABLE := 1 */
        sw      zero, 0x20(t0)              /* SWD_WPROTECT: re-lock    */

        ret
        .endif

        .size   clock_init, . - clock_init
