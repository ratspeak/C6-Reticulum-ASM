# ============================================================================
# @function:    _reset
# @module:      boot
# @inputs:      (none; entered from reset / qemu kernel load)
# @outputs:     (transfers to _main; never returns)
# @clobbers:    sp, gp, t0..t6, a0..a7, ra
# @preserves:   (none — initial state is undefined)
# @stack:       0
# @cycles:      bounded (~50)
# @ct:          not-required
# @spec:        ESP32-C6 TRM §3 (Reset and Boot); milestone-1 §boot
# @verify:      kat-only; entry-point semantics, no functional contract
# @tests:       tests/boot/test__reset.py
# @adrs:        0001, 0002, 0008
# @status:      verified
# ============================================================================

/* Reset vector. Establishes the C calling environment (stack pointer +
 * global pointer) and enters _main. Per ADR-0002 the stack region is
 * statically defined by the linker script (`__stack_top`); per ADR-0001
 * sp is 16-byte aligned at function entry. _init_bss / _init_data are
 * called by _main once the basic environment is up.
 *
 * The `.option norelax` brackets the `la gp, __global_pointer$` load —
 * linker relaxation would otherwise replace it with a gp-relative add,
 * but gp is the very thing we are setting, so we need the absolute load.
 */

        .section .text._reset, "ax", @progbits
        .global _reset
        .type   _reset, @function
_reset:
        la      sp, __stack_top

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

        call    _main

        /* Defensive: if _main ever returns, halt forever. */
1:      wfi
        j       1b

        .size   _reset, . - _reset
