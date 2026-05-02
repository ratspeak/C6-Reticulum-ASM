# ============================================================================
# @function:    log_hex_buf
# @module:      log
# @inputs:      a0 = ptr (buffer), a1 = len (bytes)
# @outputs:     (`len` byte values emitted as 2*len contiguous hex chars; no separators)
# @clobbers:    a0, a1, t0, t1, t2
# @preserves:   sp, gp, ra, s0, s1, all other callee-saved
# @stack:       16
# @cycles:      bounded (len × ~12 cycles + uart polling)
# @ct:          not-required
# @spec:        ADR-0004 §API; complement to log_bytes (which inserts spaces)
# @verify:      kat-only; thin loop over log_hex(width=2)
# @tests:       tests/log/test_log_hex_buf.py
# @adrs:        0004
# @status:      verified
# ============================================================================

/* Emit a byte buffer as 2*len contiguous hex chars (lowercase, no
 * separators). Used for binary log fields where the value must satisfy
 * the log-line format's no-whitespace constraint (e.g., a 32-byte hash
 * digest emitted as 64 hex chars).
 *
 * Frame: 16 bytes (ra/s0/s1). s0 = read cursor, s1 = remaining count.
 */

        .section .text.log_hex_buf, "ax", @progbits
        .global log_hex_buf
        .type   log_hex_buf, @function
log_hex_buf:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)
        mv      s0, a0
        mv      s1, a1
1:      beqz    s1, 9f
        lbu     a0, 0(s0)
        li      a1, 2
        call    log_hex
        addi    s0, s0, 1
        addi    s1, s1, -1
        j       1b
9:      lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   log_hex_buf, . - log_hex_buf
