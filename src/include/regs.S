/* Peripheral register addresses.
 *
 * Two targets are supported:
 *
 *   * `qemu-virt`  — qemu's `virt` machine, rv32 variant. NS16550A UART
 *                    at 0x10000000; main RAM at 0x80000000.
 *   * `c6`         — the Adafruit ESP32-C6 Feather. HP_SRAM at
 *                    0x4080_0000 (512 KiB); USB Serial/JTAG at 0x60043000
 *                    is the early-bring-up serial backend (UART0 over
 *                    GPIO16/17 is also defined — landing once a wired
 *                    USB-serial dongle is on bench).
 *
 * Selected at assembly time via `--defsym TARGET_QEMU_VIRT=1` or
 * `--defsym TARGET_C6=1`. The Makefile defaults to qemu-virt.
 *
 * Uses GAS-native conditional directives only; no C preprocessor.
 */

        .ifndef TARGET_C6
        .ifndef TARGET_QEMU_VIRT
        .equ    TARGET_QEMU_VIRT, 1
        .endif
        .endif

        /* --- qemu-virt (NS16550A 8-bit registers, byte-stride) --- */
        .ifdef  TARGET_QEMU_VIRT
        .equ    UART0_BASE,         0x10000000
        .equ    UART0_THR,          UART0_BASE + 0x00   /* TX holding (W)  */
        .equ    UART0_RBR,          UART0_BASE + 0x00   /* RX buffer  (R)  */
        .equ    UART0_IER,          UART0_BASE + 0x01   /* IRQ enable      */
        .equ    UART0_LSR,          UART0_BASE + 0x05   /* line status     */
        .equ    UART0_LSR_THRE,     0x20                /* TX holding empty */
        .equ    UART0_LSR_DR,       0x01                /* RX data ready    */
        .equ    DRAM_BASE,          0x80000000
        /* CLINT (RISC-V Privileged spec §3.2). qemu-virt places it at
         * 0x02000000; mtime is a 64-bit memory-mapped counter at
         * +0xbff8 ticking at 10 MHz. */
        .equ    CLINT_BASE,         0x02000000
        .equ    CLINT_MTIME_LO,     CLINT_BASE + 0xbff8
        .equ    CLINT_MTIME_HI,     CLINT_BASE + 0xbffc
        .equ    MTIME_HZ,           10000000            /* 10 MHz on virt   */
        .equ    MTIME_TICKS_PER_MS, 10000                /* MTIME_HZ / 1000  */
        .equ    MTIME_TICKS_PER_US, 10                   /* MTIME_HZ / 1e6   */
        /* CPU rate on qemu's rv32 default; documented "indicative" only
         * — qemu does not rate-limit the host CPU. Callers that need
         * wall-clock timing must use mtime, not cycle counts. */
        .equ    CPU_HZ,             100000000           /* 100 MHz nominal  */
        .endif

        /* --- ESP32-C6 (Adafruit Feather ESP32-C6, RV32IMAC) --- */
        /* Sources: ESP32-C6 TRM r1.4 Ch 4 (Memory Map), Ch 11 (SYSTIMER),
         * Ch 33 (UART), Ch 36 (USB Serial/JTAG). HP_SRAM is 0x4080_0000–
         * 0x4087_FFFF (512 KiB, all of which is ours after the mask-ROM
         * boot loader hands off; the ROM is one-shot and its scratch
         * does not survive into our run-time). The SYSTIMER unit0 counts
         * at 16 MHz (XTAL/2.5) regardless of CPU clock; the boot ROM
         * enables it before handing off, so callers may read directly. */
        .ifdef  TARGET_C6
        /* Full HP_SRAM extent is 0x4080_0000 - 0x4088_0000 (512 KiB). The
         * lower half overlaps the mask-ROM's flash-loader scratch and is
         * unsafe to LOAD into during boot, so the linker script targets
         * only the upper "bootloader region" 0x4086_C410 - 0x4087_C610
         * (the same one esp-idf's own second-stage bootloader uses). */
        .equ    HPSRAM_BASE,        0x40800000
        .equ    HPSRAM_SIZE,        0x00080000          /* 512 KiB         */

        /* ADR-0004 names UART0 as the diagnostic transport. The C6 also
         * hosts a USB Serial/JTAG controller (TRM Ch 36) which is what
         * /dev/cu.usbmodemNNNN enumerates over the on-board USB-C jack —
         * no external dongle. The USJ peripheral is the early-bring-up
         * backend for the uart_* primitives; the GPIO16/17 UART0 path
         * lands once a wired dongle is on bench. See the deviation note
         * in docs/milestones/milestone-1.md §uart. */
        .equ    USJ_BASE,           0x6000F000
        .equ    USJ_EP1,            USJ_BASE + 0x00     /* TX/RX FIFO byte  */
        .equ    USJ_EP1_CONF,       USJ_BASE + 0x04     /* control + status */
        .equ    USJ_WR_DONE,        0x01                /* flush IN endpoint */
        .equ    USJ_IN_EP_FREE,     0x02                /* TX FIFO has room  */
        .equ    USJ_OUT_EP_DATA,    0x04                /* RX FIFO has byte  */

        /* Compatibility aliases so target-agnostic call sites that load
         * UART0_BASE keep linking. Polled paths in uart_tx_byte / _rx_byte
         * select on .ifdef TARGET_C6 and never touch the NS16550A bits. */
        .equ    UART0_BASE,         USJ_BASE
        .equ    UART0_LSR,          USJ_EP1_CONF
        .equ    UART0_LSR_THRE,     USJ_IN_EP_FREE
        .equ    UART0_LSR_DR,       USJ_OUT_EP_DATA

        /* SYSTIMER UNIT0: 64-bit free-running counter. Reads require a
         * snapshot trigger, then poll-for-valid, then load HI/LO. The
         * HI register is at the lower offset (0x40) — same convention
         * as the rest of the ESP32 family. */
        .equ    SYSTIMER_BASE,      0x6000A000
        .equ    SYSTIMER_UNIT0_OP,  SYSTIMER_BASE + 0x04
        .equ    SYSTIMER_UNIT0_HI,  SYSTIMER_BASE + 0x40
        .equ    SYSTIMER_UNIT0_LO,  SYSTIMER_BASE + 0x44
        .equ    SYSTIMER_UNIT0_UPDATE,    0x40000000    /* bit 30 (W)      */
        .equ    SYSTIMER_UNIT0_VALID,     0x20000000    /* bit 29 (R)      */
        .equ    MTIME_HZ,           16000000            /* SYSTIMER tick    */
        .equ    MTIME_TICKS_PER_MS, 16000
        .equ    MTIME_TICKS_PER_US, 16
        /* CPU rate after the mask-ROM hand-off. The ROM stage configures
         * the PLL for its XIP path; documented-typical is 80 MHz. We do
         * not reconfigure in clock_init this milestone — that lands when
         * we need 160 MHz for the LoRa SPI burst loop in milestone 8. */
        .equ    CPU_HZ,             80000000
        .equ    DRAM_BASE,          HPSRAM_BASE

        /* Watchdog timers — three of them, all enabled by the boot ROM
         * before hand-off, all writeable only after writing the magic
         * key to the matching WPROTECT register. clock_init disables
         * each so the milestone-1 polling main loop does not get reset.
         * Per-key value is the same 0x50D83AA1 across TIMG / LP / SWD
         * (mwdt_ll.h, lpwdt_ll.h). */
        .equ    TIMG0_BASE,         0x60008000
        .equ    TIMG0_WDTCONFIG0,   TIMG0_BASE + 0x48
        .equ    TIMG0_WDTWPROTECT,  TIMG0_BASE + 0x64
        .equ    LP_WDT_BASE,        0x600B1C00
        .equ    LP_WDT_CONFIG0,     LP_WDT_BASE + 0x00
        .equ    LP_WDT_WPROTECT,    LP_WDT_BASE + 0x18
        .equ    LP_WDT_SWD_CONFIG,  LP_WDT_BASE + 0x1C
        .equ    LP_WDT_SWD_WPROTECT, LP_WDT_BASE + 0x20
        .equ    WDT_WKEY,           0x50D83AA1
        .equ    LP_WDT_SWD_DISABLE, 0x40000000  /* bit 30 of SWD_CONFIG */

        /* On-chip RNG. The LPPERI block exposes the hardware RNG as a
         * single 32-bit register. The mask ROM enables the LP-peripheral
         * clock for its own boot work, so we can read directly without a
         * peripheral-clock-enable dance. Per the C6 TRM the analog noise
         * source feeds the PRNG continuously; reading consumes no entropy.
         * Without WiFi/BLE the RNG output is pseudo-random with a
         * hardware-seeded state — adequate as a milestone-2 RNG until the
         * production HMAC-DRBG (NIST SP 800-90A) lands. */
        .equ    LPPERI_BASE,        0x600B2800
        .equ    LPPERI_RNG_DATA,    LPPERI_BASE + 0x08
        .endif
