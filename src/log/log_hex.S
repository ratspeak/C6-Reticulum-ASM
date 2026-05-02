# ============================================================================
# @function:    log_hex
# @module:      log
# @inputs:      a0 = value (32-bit), a1 = width (1..8 hex digits to emit)
# @outputs:     (`width` ASCII hex digits emitted on UART0; lowercase a-f)
# @clobbers:    a0, t0, t1, t2
# @preserves:   sp, gp, ra, s0, s1, all other callee-saved
# @stack:       16
# @cycles:      bounded (width × ~10 + uart polling)
# @ct:          not-required
# @spec:        ADR-0004 §API; ADR-0008 (timestamps are 8 hex digits)
# @verify:      kat-only; integration-tested via log_event banner in tests/log/test_log_event.py
# @tests:       tests/log/test_log_hex.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* Emit `width` hex digits (lowercase) for the value in a0, MSB first.
 *
 * Loop invariant: s1 = remaining digits to emit; s0 = original value
 * (immutable). Each iteration extracts nibble #(s1-1) by shifting right
 * (s1-1)*4 bits. Width 0 produces no output.
 *
 * Frame: 16 bytes for ra + s0 + s1 (16-byte aligned).
 */

        .section .text.log_hex, "ax", @progbits
        .global log_hex
        .type   log_hex, @function
log_hex:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)
        mv      s0, a0                  /* value (constant across iters) */
        mv      s1, a1                  /* remaining digit count        */
1:      beqz    s1, 9f
        addi    t0, s1, -1              /* nibble index (0 = lowest)    */
        slli    t0, t0, 2               /* shift count = idx * 4         */
        srl     t1, s0, t0
        andi    t1, t1, 0xF             /* nibble in low 4               */
        li      t2, 10
        blt     t1, t2, 2f
        addi    a0, t1, 87              /* 'a' - 10 = 87                 */
        j       3f
2:      addi    a0, t1, 48              /* '0' = 48                      */
3:      call    uart_tx_byte
        addi    s1, s1, -1
        j       1b
9:      lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   log_hex, . - log_hex
