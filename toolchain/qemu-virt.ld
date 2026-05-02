/* Linker script for the qemu-system-riscv32 `virt` machine.
 *
 * Memory layout per qemu's virt model:
 *   0x0000_1000 - 0x0001_1000   mrom (boot rom, read-only)
 *   0x1000_0000                  uart0 (NS16550A)
 *   0x8000_0000 +                main RAM (default 8 MiB; resizable via -m)
 *
 * `qemu -kernel <elf>` loads at the ELF entry point address. We place the
 * entire image at DRAM_BASE = 0x80000000.
 *
 * Per ADR-0002 every byte of statically-allocated RAM is accounted for at
 * link time. The .stack region is reserved at the top of DRAM; the
 * static stack-depth analyzer (tools/check_stack.py, deferred per OQ-4)
 * asserts the worst-case call depth fits.
 *
 * The C6-target linker script (toolchain/c6.ld) lands when real-hardware
 * bring-up starts; this file is the qemu-only entry.
 */

OUTPUT_ARCH("riscv")
OUTPUT_FORMAT("elf32-littleriscv")
ENTRY(_reset)

MEMORY
{
    DRAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M
}

SECTIONS
{
    . = ORIGIN(DRAM);

    .text : ALIGN(4) {
        __text_start = .;
        KEEP(*(.text._reset))   /* reset vector first */
        *(.text*)
        __text_end = .;
    } > DRAM

    .rodata : ALIGN(4) {
        *(.rodata*)
    } > DRAM

    .data : ALIGN(4) {
        __data_start = .;
        *(.data*)
        __data_end = .;
    } > DRAM

    /* GP convention: gp points 0x800 above the start of small data so
       gp-relative loads can reach ±2 KiB on either side. We have no .sdata
       yet, so anchor it at the .data start; the value is consumed by the
       `la gp, __global_pointer$` in _reset. */
    PROVIDE(__global_pointer$ = __data_start + 0x800);

    .bss : ALIGN(4) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > DRAM

    /* Stack at the top of the loaded image; grows down. STACK_SIZE comes
       from src/include/config.S (16 KiB). */
    . = ALIGN(16);
    __stack_bottom = .;
    . += 0x4000;
    __stack_top = .;
    __image_end = .;
}
