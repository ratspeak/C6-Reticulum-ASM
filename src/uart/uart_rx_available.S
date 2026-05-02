# ============================================================================
# @function:    uart_rx_available
# @module:      uart
# @inputs:      (none)
# @outputs:     a0 = 1 if a byte is available, 0 otherwise
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~5)
# @ct:          not-required
# @spec:        NS16550A datasheet (qemu-virt); milestone-1 §uart
# @verify:      kat-only; thin polled hardware read
# @tests:       tests/uart/test_uart_rx_available.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* Returns 1 iff LSR.DR is set (a byte is sitting in RBR ready to be
 * read), 0 otherwise. Non-blocking. The eventual IRQ-driven version
 * will return the count of bytes in the RX ring buffer; for the polled
 * NS16550A path the return is 0/1 since the FIFO is hidden behind a
 * single-byte hardware register from our point of view.
 */

        .include "regs.S"

        .section .text.uart_rx_available, "ax", @progbits
        .global uart_rx_available
        .type   uart_rx_available, @function
uart_rx_available:
        li      t0, UART0_BASE
        lbu     t1, 5(t0)
        andi    a0, t1, UART0_LSR_DR
        ret

        .size   uart_rx_available, . - uart_rx_available
