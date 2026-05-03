# ============================================================================
# @function:    announce_send
# @module:      announce
# @inputs:      a0 = identity_t*, a1 = name_hash ptr (10 bytes), a2 = app_data ptr (may be 0 when app_data_len = 0), a3 = app_data_len
# @outputs:     a0 = raw announce length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, all callee-saved
# @stack:       0
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-3 announce_send; KISS-framed Reticulum announce TX path
# @verify:      proofs/announce/announce_tx.tla
# @tests:       tests/announce/test_announce_send.py
# @adrs:        0001, 0002, 0004, 0006, 0009
# @status:      draft
# ============================================================================

/* Stub owned by Agent 2. The implementation will build a raw HEADER_1
 * announce, KISS-frame it into the static TX buffer, write it to UART, and
 * return the raw announce length. Secret-key CT is owned by announce_build
 * and crypto callees; the post-build KISS/UART bytes are public output.
 */

        .section .text.announce_send, "ax", @progbits
        .global announce_send
        .type   announce_send, @function
announce_send:
        unimp

        .size   announce_send, . - announce_send
