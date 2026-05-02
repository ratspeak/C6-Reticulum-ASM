# ============================================================================
# @function:    _init_bss
# @module:      boot
# @inputs:      (none; reads __bss_start/__bss_end linker symbols)
# @outputs:     (.bss zeroed)
# @clobbers:    t0, t1, t2
# @preserves:   sp, gp, ra
# @stack:       0
# @cycles:      bounded (4 + 1 per word)
# @ct:          not-required
# @spec:        milestone-1 §boot; ADR-0002
# @verify:      kat-only; trivial memory zeroing
# @tests:       tests/boot/test__init_bss.py
# @adrs:        0002
# @status:      draft
# ============================================================================

/* Zero the .bss region between linker symbols __bss_start and __bss_end.
 * Stub; real implementation lands as part of the bring-up chain.
 */

        .section .text._init_bss, "ax", @progbits
        .global _init_bss
        .type   _init_bss, @function
_init_bss:
        unimp
        .size   _init_bss, . - _init_bss
