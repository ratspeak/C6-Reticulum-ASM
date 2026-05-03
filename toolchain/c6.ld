/* Linker script for the Adafruit ESP32-C6 Feather (RV32IMAC).
 *
 * Memory layout (per ESP32-C6 TRM r1.4 Ch 4 "System and Memory" + the
 * esp-idf bootloader linker script's documented ROM scratch map):
 *   0x4080_0000 - 0x4086_C410   HP_SRAM low half — used by the mask-ROM
 *                                during SPI flash boot (download-mode
 *                                shared buffers, flash-read scratch,
 *                                segment-loader workspace). Loading our
 *                                image here corrupts the ROM's working
 *                                memory while the load is in progress —
 *                                empirically this triggers a checksum
 *                                failure with calculated == seed (0xef),
 *                                meaning the XOR walk over our segment
 *                                data never completes.
 *   0x4086_C410 - 0x4087_C610   HP_SRAM upper half — esp-idf's own
 *                                second-stage bootloader lives here
 *                                (bootloader.ld:bootloader_iram_seg_start
 *                                etc.). Safe for OUR second-stage image
 *                                because the ROM has finished its boot
 *                                work by the time we land here.
 *   0x4087_C610 - 0x4087_E610   ROM PRO-CPU stack (in use throughout)
 *   0x4087_E610 - 0x4088_0000   ROM .bss/.data (in use throughout)
 *   0x6000_0000 +               High-peripheral block (UART, USJ, SYSTIMER…)
 *   Flash (XIP)                 0x4200_0000 — not used this milestone;
 *                                everything lives in HP_SRAM.
 *
 * We load the entire image into the upper HP_SRAM bootloader region
 * starting at 0x4086_C410 — same address esp-idf's own bootloader uses,
 * which is the most thoroughly-tested ROM hand-off path. Total budget
 * is 0x4087_C610 - 0x4086_C410 = 64 KiB for .text + .rodata + .data +
 * .bss + .stack; a 16 KiB stack leaves 48 KiB for code/data, which
 * accommodates the current ~30 KiB image with room to grow before the
 * crypto KAT bridge starts pushing the .text size.
 *
 * LMA == VMA throughout (the ROM loader copies each PT_LOAD segment
 * into HP_SRAM at the documented load address); _init_data's copy loop
 * still runs but every iteration is a no-op, matching the qemu-virt
 * path. Stack grows down from __stack_top (top of the reserved 16 KiB
 * region); tools/check_stack.py asserts worst-case depth fits.
 */

OUTPUT_ARCH("riscv")
OUTPUT_FORMAT("elf32-littleriscv")
ENTRY(_reset)

/* 0x4086_C410 + 64 KiB = 0x4087_C410 — keeps us 0x200 bytes below the
 * ROM stack at 0x4087_C610. */
MEMORY
{
    HPSRAM (rwx) : ORIGIN = 0x4086C410, LENGTH = 64K
}

SECTIONS
{
    . = ORIGIN(HPSRAM);

    .text : ALIGN(4) {
        __text_start = .;
        KEEP(*(.text._reset))   /* reset vector first */
        *(.text*)
        __text_end = .;
    } > HPSRAM

    .rodata : ALIGN(4) {
        *(.rodata*)
    } > HPSRAM

    .data : ALIGN(4) {
        __data_start = .;
        *(.data*)
        __data_end = .;
    } > HPSRAM

    /* On the C6 the ROM loader installs each segment at its LMA in SRAM,
       so LMA == VMA and _init_data's copy loop is a per-word no-op (same
       as qemu-virt). The contract is preserved for the day .data lives
       in flash and needs an actual XIP-to-SRAM copy. */
    __data_load_start = LOADADDR(.data);

    /* GP convention: gp points 0x800 above the start of small data so
       gp-relative loads can reach ±2 KiB on either side. We have no .sdata
       yet, so anchor it at the .data start; consumed by `la gp,
       __global_pointer$` in _reset. */
    PROVIDE(__global_pointer$ = __data_start + 0x800);

    .bss : ALIGN(4) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > HPSRAM

    /* Stack at the top of the loaded image, grows down. STACK_SIZE comes
       from src/include/config.S (16 KiB). We intentionally place .stack
       right after .bss rather than at HPSRAM end so unused HP_SRAM stays
       free for future BSS growth without re-flashing the linker script. */
    . = ALIGN(16);
    __stack_bottom = .;
    . += 0x4000;
    __stack_top = .;
    __image_end = .;
}
