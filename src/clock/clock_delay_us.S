# ============================================================================
# @function:    clock_delay_us
# @module:      clock
# @inputs:      a0 = microseconds to busy-wait (must be < 2^28 ≈ 268s; larger silently truncate)
# @outputs:     (returns once at least `us` microseconds of mtime have elapsed)
# @clobbers:    a1, a2, t0, t1, t2
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      unbounded (busy-wait by design; ~us * MTIME_HZ/1e6 mtime ticks)
# @ct:          not-required
# @spec:        regs.S MTIME_TICKS_PER_US; mtime semantics from RISC-V Privileged §3.2.1
# @verify:      kat-only; integration: tests/clock/test_clock_delay_us.py wraps in clock_now_ms diff
# @tests:       tests/clock/test_clock_delay_us.py
# @adrs:        0001
# @status:      verified
# ============================================================================

/* Spin until the platform tick counter has advanced by us * TICKS_PER_US.
 *
 * Uses 32-bit modular subtraction on mtime_lo: elapsed = (now_lo -
 * start_lo) mod 2^32. This gives the correct elapsed-tick count for
 * any wait < 2^32 ticks (~429s on qemu-virt). The us*10 product also
 * has a 32-bit ceiling — we cap at us < 2^28 so the worst-case product
 * stays in 32 bits. Both bounds vastly exceed any reasonable busy-wait.
 *
 * Multiplication by 10 is encoded as (us<<3) + (us<<1) — two shifts and
 * an add, since rv32imac's `mul` is overkill for a constant factor and
 * the M extension's not available on every future target.
 */

        .include "regs.S"

        .section .text.clock_delay_us, "ax", @progbits
        .global clock_delay_us
        .type   clock_delay_us, @function
clock_delay_us:
        .ifdef TARGET_QEMU_VIRT
        slli    a1, a0, 3                /* us * 8                       */
        slli    a2, a0, 1                /* us * 2                       */
        add     a1, a1, a2               /* delta = us * 10              */
        li      t0, CLINT_MTIME_LO
        lw      t1, 0(t0)                /* start_lo                     */
1:      lw      t2, 0(t0)                /* now_lo                       */
        sub     t2, t2, t1               /* elapsed (mod 2^32)           */
        bltu    t2, a1, 1b               /* spin while elapsed < delta   */
        ret
        .endif

        .ifdef TARGET_C6
        /* C6 SYSTIMER ticks at 16 MHz, so delta = us * 16 = us << 4
         * (single-shift versus the qemu-virt three-instruction *10).
         * Each iteration re-snapshots via UPDATE/poll-VALID/read-LO
         * because the counter is not directly memory-mapped on C6 —
         * unlike CLINT.mtime, reads need an explicit trigger. We use
         * t2 as the UPDATE bitmask carried across iterations and a2
         * as a scratch for the VALID-poll result. */
        slli    a1, a0, 4                /* delta = us * 16              */
        li      t0, SYSTIMER_BASE
        li      t2, SYSTIMER_UNIT0_UPDATE
        sw      t2, 4(t0)                /* trigger snapshot             */
1:      lw      a2, 4(t0)
        srli    a2, a2, 29               /* VALID → bit 0                */
        andi    a2, a2, 1
        beqz    a2, 1b
        lw      t1, 0x44(t0)             /* start_lo                     */
2:      sw      t2, 4(t0)                /* re-trigger snapshot          */
3:      lw      a2, 4(t0)
        srli    a2, a2, 29
        andi    a2, a2, 1
        beqz    a2, 3b
        lw      a2, 0x44(t0)             /* now_lo                       */
        sub     a2, a2, t1               /* elapsed (mod 2^32)           */
        bltu    a2, a1, 2b
        ret
        .endif

        .size   clock_delay_us, . - clock_delay_us
