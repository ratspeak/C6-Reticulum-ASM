# ============================================================================
# @function:    _main
# @module:      boot
# @inputs:      (none; entered from _reset)
# @outputs:     (does not return)
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp
# @stack:       16
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-1 §boot
# @verify:      kat-only; top-level event loop, no functional contract
# @tests:       tests/boot/test__main.py
# @adrs:        0001
# @status:      draft
# ============================================================================

/* Top-level entry point. Stub: per CLAUDE.md the stub body is a single
 * `unimp` until the bring-up sequence is wired function-by-function.
 */

        .section .text._main, "ax", @progbits
        .global _main
        .type   _main, @function
_main:
        unimp
        .size   _main, . - _main
