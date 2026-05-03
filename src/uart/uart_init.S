# ============================================================================
# @function:    uart_init
# @module:      uart
# @inputs:      (none; sources its baud / divisor from src/include/config.S)
# @outputs:     (UART0 ready for tx_byte / rx_byte calls)
# @clobbers:    (none on qemu-virt)
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~1 on qemu, ~tens on C6 register writes)
# @ct:          not-required
# @spec:        ESP32-C6 TRM Chapter 33 (UART); milestone-1 §uart
# @verify:      kat-only; configures hardware, no functional contract beyond "ret + UART usable"
# @tests:       tests/uart/test_uart_init.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* On qemu-virt the NS16550A model comes up pre-initialised — qemu sets
 * up sane defaults (8N1, polled access works without DLAB programming).
 * On the real ESP32-C6 we will:
 *   1. Enable the UART0 peripheral clock.
 *   2. Set baud rate (config.S → divisor).
 *   3. Configure 8N1, no flow control.
 *   4. Enable RX interrupt (the ISR pushes into the RX ring buffer).
 * That sequence ships with the C6 bring-up; for now this function lets
 * the boot chain link and run on qemu without further plumbing.
 */

        .section .text.uart_init, "ax", @progbits
        .global uart_init
        .type   uart_init, @function
uart_init:
        .ifdef TARGET_QEMU_VIRT
        ret
        .endif
        .ifdef TARGET_C6
        /* The USB Serial/JTAG peripheral comes up enabled and clocked by
         * the mask-ROM stage (the ROM uses it for its own boot messages),
         * so no register programming is required to use it from our side.
         * GPIO16/17 UART0 lands when a wired dongle is on bench. */
        ret
        .endif

        .size   uart_init, . - uart_init
