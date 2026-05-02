# ============================================================================
# @function:    log_str
# @module:      log
# @inputs:      a0 = ptr (string), a1 = len (bytes; no null terminator expected)
# @outputs:     (string emitted on UART0)
# @clobbers:    t0, t1, a0
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      unbounded
# @ct:          not-required
# @spec:        ADR-0004 §API; milestone-1 §log
# @verify:      kat-only; thin tail-call into uart_tx_bytes
# @tests:       tests/log/test_log_str.py
# @adrs:        0004
# @status:      verified
# ============================================================================

/* Tail-call: forward (a0, a1) to uart_tx_bytes. ra is still the caller's
 * ra on entry; uart_tx_bytes saves and restores it through its own
 * prologue/epilogue. We do not need a frame.
 *
 * The function exists as a separate symbol so log_event and downstream
 * primitives can call `log_str` without coupling to the underlying TX
 * implementation — the day uart_tx_bytes becomes IRQ-driven, only this
 * forwarder changes.
 */

        .section .text.log_str, "ax", @progbits
        .global log_str
        .type   log_str, @function
log_str:
        tail    uart_tx_bytes
        .size   log_str, . - log_str
