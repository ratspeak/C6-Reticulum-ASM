/* Peripheral register addresses.
 *
 * Two targets are supported:
 *
 *   * `qemu-virt`  — qemu's `virt` machine, rv32 variant. NS16550A UART
 *                    at 0x10000000; main RAM at 0x80000000.
 *   * `c6`         — the real Adafruit ESP32-C6 Feather. UART0 in the
 *                    high-peripheral region (TBD; populated when first
 *                    real bring-up lands).
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

        /* --- ESP32-C6 (TBD; bring-up is wave 2 of milestone 1) --- */
        .ifdef  TARGET_C6
        .error  "TARGET_C6 register definitions not populated yet"
        .endif
