# ============================================================================
# @function:    log_bytes
# @module:      log
# @inputs:      a0 = ptr (buffer), a1 = len (bytes)
# @outputs:     (`len` byte values emitted as space-separated hex pairs)
# @clobbers:    a0, a1, t0, t1, t2
# @preserves:   sp, gp, ra, s0, s1, all other callee-saved
# @stack:       16
# @cycles:      bounded (len × ~30 cycles + uart polling)
# @ct:          not-required
# @spec:        ADR-0004 §API; milestone-1 §log
# @verify:      kat-only; thin loop over log_hex
# @tests:       tests/log/test_log_bytes.py
# @adrs:        0004
# @status:      verified
# ============================================================================

/* Emit a byte buffer as space-separated 2-digit hex pairs:
 *   "ab cd ef …"
 * Used by log_event payload-printing of binary fields. The space
 * separator goes BEFORE every digit pair except the first; an empty
 * buffer (len == 0) emits nothing.
 *
 * Frame: 16 bytes for ra/s0/s1 (s0 = cursor, s1 = remaining count).
 */

        .section .text.log_bytes, "ax", @progbits
        .global log_bytes
        .type   log_bytes, @function
log_bytes:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)
        mv      s0, a0                  /* cursor                        */
        mv      s1, a1                  /* remaining count               */

        beqz    s1, .Ldone

        /* First byte: no leading space. */
        lbu     a0, 0(s0)
        li      a1, 2
        call    log_hex
        addi    s0, s0, 1
        addi    s1, s1, -1

        /* Subsequent bytes: emit ' ' then the hex pair. */
1:      beqz    s1, .Ldone
        li      a0, 32                  /* ' '                           */
        call    uart_tx_byte
        lbu     a0, 0(s0)
        li      a1, 2
        call    log_hex
        addi    s0, s0, 1
        addi    s1, s1, -1
        j       1b

.Ldone:
        lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   log_bytes, . - log_bytes
