# ============================================================================
# @function:    log_event
# @module:      log
# @inputs:      a0 = tag ptr, a1 = tag len
# @outputs:     (one structured log line emitted on UART0)
# @clobbers:    a0, a1, t0..t6, ra
# @preserves:   sp, gp, s0, s1, all other callee-saved
# @stack:       16
# @cycles:      bounded (~120 + uart polling)
# @ct:          not-required
# @spec:        ADR-0004 (log line format), ADR-0008 (timestamp = 8 hex digits)
# @verify:      kat-only; integration via tests/log/test_log_event.py (qemu run)
# @tests:       tests/log/test_log_event.py
# @adrs:        0004, 0008
# @status:      verified
# ============================================================================

/* Emit one structured log line:
 *
 *     <ts8hex>\t<tag>\r\n
 *
 * `tag` is supplied by the caller pre-baked as `<module>\t<event>`
 * (e.g. "boot\tready"). The timestamp is 8 hex digits per ADR-0008.
 *
 * The timestamp source is not yet wired (clock_get_freq lands later),
 * so log_event currently emits 00000000. The wire format is final;
 * only the value sampled by log_hex changes when the timer is ready.
 *
 * Frame: 16 bytes for ra + s0 + s1 (16-byte aligned). s0 holds the
 * tag pointer and s1 the tag length across the inner calls.
 */

        .section .text.log_event, "ax", @progbits
        .global log_event
        .type   log_event, @function
log_event:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)
        mv      s0, a0                  /* tag_ptr                       */
        mv      s1, a1                  /* tag_len                       */

        /* Timestamp: 8 hex digits. Placeholder value 0 until the timer
         * source (clock_get_freq) is wired. */
        li      a0, 0
        li      a1, 8
        call    log_hex

        /* '\t' = 9 */
        li      a0, 9
        call    uart_tx_byte

        /* Tag (pre-baked "module\tevent"). */
        mv      a0, s0
        mv      a1, s1
        call    log_str

        /* '\r' = 13, '\n' = 10 */
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte

        lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   log_event, . - log_event
