# ============================================================================
# @function:    uart_rx_byte
# @module:      uart
# @inputs:      (none)
# @outputs:     a0 = received byte (low 8 bits; high bits zero)
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      unbounded
# @ct:          not-required
# @spec:        NS16550A datasheet (qemu-virt) / ESP32-C6 TRM Ch 33; milestone-1 §uart
# @verify:      kat-only; thin polled hardware read
# @tests:       tests/uart/test_uart_rx_byte.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* Polled NS16550A RX (qemu-virt):
 *   1. Spin on LSR.DR (bit 0 of LSR @ base+5) until a byte is available.
 *   2. Read it from RBR (base+0).
 *
 * Blocking, no timeout. The interrupt-driven path with ring buffers
 * (per ADR-0004) ships when uart_isr lands; this polled variant is the
 * bring-up version and stays as a fall-back used before IRQ wiring.
 */

        .include "regs.S"

        .section .text.uart_rx_byte, "ax", @progbits
        .global uart_rx_byte
        .type   uart_rx_byte, @function
uart_rx_byte:
        li      t0, UART0_BASE
1:      lbu     t1, 5(t0)               /* LSR                          */
        andi    t1, t1, UART0_LSR_DR
        beqz    t1, 1b
        lbu     a0, 0(t0)               /* RBR                          */
        ret

        .size   uart_rx_byte, . - uart_rx_byte
