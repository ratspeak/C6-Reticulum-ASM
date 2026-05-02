# ============================================================================
# @function:    kiss_decode_reset
# @module:      kiss
# @inputs:      (none)
# @outputs:     (kiss decoder state cleared: in_frame=0, escaped=0, saw_type=0, buf_len=0)
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~6)
# @ct:          not-required
# @spec:        KISS spec (Karn 1986); milestone-1 §kiss
# @verify:      kat-only; trivial state zeroing
# @tests:       tests/kiss/test_kiss_decode_reset.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Clear the kiss decoder state. Used on framing error and when the
 * caller wants to discard a partial frame. The buf bytes themselves
 * are not zeroed — buf_len = 0 makes them irrelevant.
 */

        .section .text.kiss_decode_reset, "ax", @progbits
        .global kiss_decode_reset
        .type   kiss_decode_reset, @function
kiss_decode_reset:
        la      t0, kiss_in_frame
        sb      zero, 0(t0)             /* in_frame                      */
        sb      zero, 1(t0)             /* escaped                       */
        sb      zero, 2(t0)             /* saw_type                      */
        la      t1, kiss_buf_len
        sw      zero, 0(t1)
        ret

        .size   kiss_decode_reset, . - kiss_decode_reset
