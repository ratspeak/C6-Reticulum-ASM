# ============================================================================
# @function:    clock_now_ms
# @module:      clock
# @inputs:      (none)
# @outputs:     a0 = milliseconds since boot, low 32 bits (wraps every ~49.7 days)
# @clobbers:    a0, a1, a2, a3, a4, a5, t0, t1, t2, ra
# @preserves:   sp, gp, all callee-saved
# @stack:       16
# @cycles:      bounded (~6 + ~64 * 8 ≈ 520 instructions)
# @ct:          not-required
# @spec:        ADR-0008 (8-hex-digit ms timestamp); MTIME_TICKS_PER_MS in regs.S
# @verify:      kat-only; integration via tests/clock/test_clock_now_ms.py and the boot.ready timestamp in test_log_event.py
# @tests:       tests/clock/test_clock_now_ms.py
# @adrs:        0001, 0008
# @status:      verified
# ============================================================================

/* Read the platform's monotonic tick counter and convert to milliseconds.
 *
 * Returns only the low 32 bits because ADR-0008 fixes the timestamp at
 * 8 hex digits (4.29 billion ms ≈ 49.7 days). Past that it wraps.
 *
 * Implementation: fetch 64-bit ticks via clock_now_ticks, then divide
 * by MTIME_TICKS_PER_MS (10000 on qemu-virt). RV32 has no native
 * 64-bit divide, so we open-code 64 iterations of restoring shift-and-
 * subtract long division. The running remainder fits in a single
 * 32-bit register (always < divisor < 2^14).
 *
 * Frame: 16 bytes, only ra spilled (16-byte SP alignment required).
 */

        .include "regs.S"

        .section .text.clock_now_ms, "ax", @progbits
        .global clock_now_ms
        .type   clock_now_ms, @function
clock_now_ms:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        call    clock_now_ticks         /* a0=ticks_lo, a1=ticks_hi      */

        /* Long division of (a1:a0) by MTIME_TICKS_PER_MS.
         *   a0 = n_lo (shifted out)        a3 = q_lo (built bit-by-bit)
         *   a1 = n_hi (shifted out)        a4 = q_hi (built bit-by-bit; discarded)
         *   a2 = divisor                   a5 = running remainder (< divisor)
         *   t0 = iteration counter         t1, t2 = temps
         */
        li      a2, MTIME_TICKS_PER_MS
        li      a3, 0
        li      a4, 0
        li      a5, 0
        li      t0, 64
1:      srli    t1, a1, 31              /* MSB of dividend → r          */
        srli    t2, a0, 31              /* MSB of n_lo → next n_hi LSB  */
        slli    a1, a1, 1
        or      a1, a1, t2
        slli    a0, a0, 1
        slli    a5, a5, 1
        or      a5, a5, t1
        srli    t2, a3, 31              /* shift q left across the pair */
        slli    a4, a4, 1
        or      a4, a4, t2
        slli    a3, a3, 1
        bltu    a5, a2, 2f              /* if r < d, no subtract        */
        sub     a5, a5, a2
        ori     a3, a3, 1
2:      addi    t0, t0, -1
        bnez    t0, 1b

        mv      a0, a3                  /* return q_lo                   */
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   clock_now_ms, . - clock_now_ms
