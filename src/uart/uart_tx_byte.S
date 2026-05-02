# ============================================================================
# @function:    uart_tx_byte
# @module:      uart
# @inputs:      a0 = byte to transmit (low 8 bits; high bits ignored)
# @outputs:     (byte placed in UART0 TX FIFO)
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      unbounded (busy-wait on THRE; bounded ~1 baud-time per byte)
# @ct:          not-required
# @spec:        NS16550A datasheet (qemu-virt) / ESP32-C6 TRM Ch 33 (C6); milestone-1 §uart
# @verify:      kat-only; thin hardware-poke wrapper, contract is "byte appears on TX"
# @tests:       tests/uart/test_uart_tx_byte.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* NS16550A polled TX (qemu-virt):
 *   1. Spin on LSR.THRE (bit 5 of LSR @ base+5) until the transmit
 *      holding register is empty.
 *   2. Write a0 to THR (base+0).
 *
 * The function is a leaf and does not save ra. The poll loop is
 * unbounded in principle (no observable timeout), but in practice
 * one baud-time bounds it; we mark @cycles unbounded honestly rather
 * than fake an upper bound.
 *
 * On the C6 the same API will dispatch to either an interrupt-driven
 * ring-buffer enqueue (the production path) or a polled fall-back used
 * before uart_isr is wired. The qemu-virt build keeps the polled form
 * permanently because qemu lacks the IRQ controller plumbing we will
 * need on hardware.
 */

        .include "regs.S"

        .section .text.uart_tx_byte, "ax", @progbits
        .global uart_tx_byte
        .type   uart_tx_byte, @function
uart_tx_byte:
        li      t0, UART0_BASE
1:      lbu     t1, 5(t0)               /* LSR */
        andi    t1, t1, UART0_LSR_THRE
        beqz    t1, 1b
        sb      a0, 0(t0)               /* THR */
        ret

        .size   uart_tx_byte, . - uart_tx_byte
