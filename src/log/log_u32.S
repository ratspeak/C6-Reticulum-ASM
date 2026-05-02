# ============================================================================
# @function:    log_u32
# @module:      log
# @inputs:      a0 = unsigned 32-bit value
# @outputs:     (decimal digits emitted on UART0; no leading zeros except for 0)
# @clobbers:    a0, t0, t1, t2
# @preserves:   sp, gp, ra, s0, s1, all other callee-saved
# @stack:       32
# @cycles:      bounded (≤ 11 × ~10 cycles + uart polling)
# @ct:          not-required
# @spec:        ADR-0004 §API; milestone-1 §log
# @verify:      kat-only; integration via tests/log/test_log_u32.py (qemu run)
# @tests:       tests/log/test_log_u32.py
# @adrs:        0001, 0004
# @status:      verified
# ============================================================================

/* Build digits LSB-first into a stack buffer, then emit MSB-first.
 * Max u32 is 4294967295 — 10 digits. The buffer is 16 bytes for
 * convenient 16-byte stack alignment.
 *
 * Frame layout (32 bytes):
 *   sp + 0..15   digit buffer
 *   sp + 16      s1 (digit count / emit cursor remaining)
 *   sp + 20      s0 (read cursor during emit phase)
 *   sp + 24      (padding)
 *   sp + 28      ra
 *
 * Special case: value == 0 emits '0' (a single digit), short-circuiting
 * the divide loop which would otherwise produce no digits.
 */

        .section .text.log_u32, "ax", @progbits
        .global log_u32
        .type   log_u32, @function
log_u32:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 20(sp)
        sw      s1, 16(sp)

        li      s1, 0
        beqz    a0, .Lzero

        li      t0, 10
1:      rem     t1, a0, t0              /* digit = value % 10            */
        div     a0, a0, t0              /* value /= 10                   */
        addi    t1, t1, 48              /* '0'                           */
        add     t2, sp, s1
        sb      t1, 0(t2)
        addi    s1, s1, 1
        bnez    a0, 1b
        j       .Lemit

.Lzero:
        li      t0, 48
        sb      t0, 0(sp)
        li      s1, 1

.Lemit:
        add     s0, sp, s1
        addi    s0, s0, -1              /* cursor at most-significant    */
2:      lbu     a0, 0(s0)
        call    uart_tx_byte
        addi    s0, s0, -1
        addi    s1, s1, -1
        bnez    s1, 2b

        lw      ra, 28(sp)
        lw      s0, 20(sp)
        lw      s1, 16(sp)
        addi    sp, sp, 32
        ret

        .size   log_u32, . - log_u32
