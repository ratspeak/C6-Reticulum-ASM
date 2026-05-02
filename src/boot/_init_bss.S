# ============================================================================
# @function:    _init_bss
# @module:      boot
# @inputs:      (none; reads __bss_start/__bss_end linker symbols)
# @outputs:     (.bss zeroed)
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra
# @stack:       0
# @cycles:      bounded (4 + 1 per word)
# @ct:          not-required
# @spec:        milestone-1 §boot; ADR-0002
# @verify:      kat-only; trivial memory zeroing (refinement against `memset(.bss,0,N)`)
# @tests:       tests/boot/test__init_bss.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Zero the .bss region between __bss_start and __bss_end (linker symbols).
 *
 * Both bounds are 4-byte aligned by the linker script. Loop invariant:
 * t0 ∈ [__bss_start, __bss_end] and the half-open interval [__bss_start, t0)
 * is fully zeroed. On exit t0 == t1 and the entire .bss region is zero.
 *
 * Leaf function (no spill, no call). 5 instructions in the steady state
 * (the post-loop branch is one instruction). The empty-region case is
 * handled by checking t0 == t1 at the loop head, so the body executes
 * zero times when .bss is empty.
 */

        .section .text._init_bss, "ax", @progbits
        .global _init_bss
        .type   _init_bss, @function
_init_bss:
        la      t0, __bss_start
        la      t1, __bss_end
1:      beq     t0, t1, 2f
        sw      zero, 0(t0)
        addi    t0, t0, 4
        j       1b
2:      ret

        .size   _init_bss, . - _init_bss
