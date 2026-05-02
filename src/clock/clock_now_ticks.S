# ============================================================================
# @function:    clock_now_ticks
# @module:      clock
# @inputs:      (none)
# @outputs:     a0 = ticks_lo, a1 = ticks_hi (64-bit monotonic count since boot)
# @clobbers:    a0, a1, t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~6 normal; loop retries only on mtime hi-half rollover, ~once per 7 minutes on qemu-virt)
# @ct:          not-required
# @spec:        RISC-V Privileged Architecture v20211203 §3.2.1 (machine timer); CLINT memory map (qemu-virt)
# @verify:      kat-only; integration: tests/clock/test_clock_now_ticks.py asserts monotonicity over a short window
# @tests:       tests/clock/test_clock_now_ticks.py
# @adrs:        0001
# @status:      verified
# ============================================================================

/* Read the platform's 64-bit free-running tick counter.
 *
 * On qemu-virt: CLINT mtime at 0x0200bff8 (10 MHz). Reads are 32-bit on
 * rv32, so the canonical pattern is hi/lo/hi-recheck — if the high half
 * changed across the read, the low half wrapped and we retry.
 *
 * On C6 (deferred): SYSTIMER UNIT0 with HI/LO load-and-snapshot
 * registers. Same hi/lo/hi-recheck contract, different addresses.
 *
 * Tick rate is target-specific; callers convert via MTIME_TICKS_PER_MS
 * etc. (in regs.S) or call clock_now_ms / clock_delay_us.
 */

        .include "regs.S"

        .section .text.clock_now_ticks, "ax", @progbits
        .global clock_now_ticks
        .type   clock_now_ticks, @function
clock_now_ticks:
        .ifdef TARGET_QEMU_VIRT
        li      t0, CLINT_MTIME_LO
1:      lw      t1, 4(t0)               /* hi (snapshot)                 */
        lw      a0, 0(t0)               /* lo                            */
        lw      a1, 4(t0)               /* hi (re-read)                  */
        bne     t1, a1, 1b              /* retry if hi rolled over       */
        ret
        .endif
        .ifdef TARGET_C6
        .error "clock_now_ticks for TARGET_C6 not implemented yet"
        .endif

        .size   clock_now_ticks, . - clock_now_ticks
