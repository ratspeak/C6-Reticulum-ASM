# ============================================================================
# @function:    _init_data
# @module:      boot
# @inputs:      (none; reads __data_load_start/__data_start/__data_end)
# @outputs:     (.data populated in SRAM from flash image)
# @clobbers:    t0, t1, t2, t3
# @preserves:   sp, gp, ra
# @stack:       0
# @cycles:      bounded (4 + 1 per word)
# @ct:          not-required
# @spec:        milestone-1 §boot; ADR-0002
# @verify:      kat-only; trivial memory copy
# @tests:       tests/boot/test__init_data.py
# @adrs:        0002
# @status:      draft
# ============================================================================

/* Copy .data from its load address (in flash) to its run address (in SRAM).
 * On qemu-virt this is a no-op because the kernel is loaded directly into
 * DRAM; on the C6 it copies from the flash-mapped image to SRAM. Stub
 * until the bring-up sequence is wired.
 */

        .section .text._init_data, "ax", @progbits
        .global _init_data
        .type   _init_data, @function
_init_data:
        unimp
        .size   _init_data, . - _init_data
