# ============================================================================
# @function:    _init_data
# @module:      boot
# @inputs:      (none; reads __data_load_start, __data_start, __data_end)
# @outputs:     (.data populated in SRAM from flash image)
# @clobbers:    t0, t1, t2, t3
# @preserves:   sp, gp, ra
# @stack:       0
# @cycles:      bounded (5 + 2 per word)
# @ct:          not-required
# @spec:        milestone-1 §boot; ADR-0002
# @verify:      kat-only; trivial memory copy (refinement against `memcpy(.data, load, N)`)
# @tests:       tests/boot/test__init_data.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Copy .data from its load address (LMA, in flash on the C6) to its run
 * address (VMA, in SRAM). On qemu-virt the kernel is loaded directly
 * into DRAM, so LMA == VMA and every copy is a no-op — the loop still
 * runs, demonstrating the contract holds; semantically the function is
 * (.data ← .data) on that target.
 *
 * Loop invariant: t0 ∈ [__data_start, __data_end] is the dst cursor;
 * t2 = __data_load_start + (t0 - __data_start) is the src cursor (we
 * keep them in lockstep with parallel addi). The half-open interval
 * [__data_start, t0) is fully populated.
 *
 * Leaf, no spill, no call.
 */

        .section .text._init_data, "ax", @progbits
        .global _init_data
        .type   _init_data, @function
_init_data:
        la      t0, __data_start
        la      t1, __data_end
        la      t2, __data_load_start
1:      beq     t0, t1, 2f
        lw      t3, 0(t2)
        sw      t3, 0(t0)
        addi    t0, t0, 4
        addi    t2, t2, 4
        j       1b
2:      ret

        .size   _init_data, . - _init_data
