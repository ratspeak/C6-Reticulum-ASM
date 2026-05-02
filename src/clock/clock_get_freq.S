# ============================================================================
# @function:    clock_get_freq
# @module:      clock
# @inputs:      (none)
# @outputs:     a0 = CPU frequency in Hz (target-specific compile-time constant)
# @clobbers:    a0
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (1)
# @ct:          not-required
# @spec:        regs.S CPU_HZ; ESP32-C6 TRM Ch 6 (real hw target)
# @verify:      kat-only; integration: tests/clock/test_clock_get_freq.py asserts the constant
# @tests:       tests/clock/test_clock_get_freq.py
# @adrs:        0001
# @status:      verified
# ============================================================================

/* Return the configured CPU frequency.
 *
 * Today this is a compile-time constant from regs.S (CPU_HZ). When the
 * C6 target's clock_init programs the PLL, this function will keep the
 * same contract — return whatever clock_init programmed — but may read
 * a cached value from .bss instead. Callers must treat the value as a
 * runtime read, not a literal, so that swap is invisible.
 *
 * For wall-clock timing prefer clock_now_ms / clock_delay_us; CPU_HZ
 * on qemu-virt is documented "indicative" because qemu does not
 * rate-limit the host CPU.
 */

        .include "regs.S"

        .section .text.clock_get_freq, "ax", @progbits
        .global clock_get_freq
        .type   clock_get_freq, @function
clock_get_freq:
        li      a0, CPU_HZ
        ret

        .size   clock_get_freq, . - clock_get_freq
