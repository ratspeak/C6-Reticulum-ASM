# ============================================================================
# @function:    uart_tx_bytes
# @module:      uart
# @inputs:      a0 = ptr (buffer base), a1 = len (bytes)
# @outputs:     (len bytes appear on UART0 TX)
# @clobbers:    t0, t1, a0
# @preserves:   sp, gp, ra, s0, s1, all other callee-saved
# @stack:       16
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-1 §uart
# @verify:      kat-only; trivial loop calling uart_tx_byte
# @tests:       tests/uart/test_uart_tx_bytes.py
# @adrs:        0001, 0004, 0008
# @status:      verified
# ============================================================================

/* Loop: for each of a1 bytes, load and forward to uart_tx_byte. We save
 * ra (since we call) plus s0 (buffer cursor) and s1 (remaining count)
 * in a 16-byte frame — one full 16-byte aligned frame is the smallest
 * the psABI allows.
 *
 * The cursor lives in s0 so it survives the uart_tx_byte call without
 * a re-save; same for s1. a0 is overwritten with each byte before the
 * call. The early-exit on a1 == 0 is at the loop head, so the empty-
 * buffer case spends one branch.
 */

        .section .text.uart_tx_bytes, "ax", @progbits
        .global uart_tx_bytes
        .type   uart_tx_bytes, @function
uart_tx_bytes:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)
        mv      s0, a0
        mv      s1, a1
1:      beqz    s1, 2f
        lbu     a0, 0(s0)
        call    uart_tx_byte
        addi    s0, s0, 1
        addi    s1, s1, -1
        j       1b
2:      lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   uart_tx_bytes, . - uart_tx_bytes
