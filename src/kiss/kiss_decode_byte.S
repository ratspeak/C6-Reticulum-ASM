# ============================================================================
# @function:    kiss_decode_byte
# @module:      kiss
# @inputs:      a0 = byte (low 8 bits; high bits ignored)
# @outputs:     a0 = 0 (no frame yet) | 1 (frame complete) | -1 (framing error)
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~30)
# @ct:          not-required
# @spec:        KISS spec (Karn 1986); milestone-1 §kiss
# @verify:      kat-only; differential test against tests/harness/oracle.py:kiss_decode
# @tests:       tests/kiss/test_kiss_decode_byte.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Single-byte KISS decoder. Mirrors the Python oracle in
 * tests/harness/oracle.py.kiss_decode but byte-at-a-time so a UART
 * polling loop can drive it.
 *
 * State (in src/state/kiss.S):
 *   kiss_in_frame  — true once we have seen the opening FEND
 *   kiss_saw_type  — true once we have consumed the type byte
 *   kiss_escaped   — true between FESC and its substitute
 *   kiss_buf_len   — payload bytes accumulated
 *   kiss_buf       — payload bytes (0..buf_len)
 *
 * Frame complete (returns 1) when we receive a FEND while in_frame and
 * buf_len > 0. The caller reads kiss_buf / kiss_buf_len before driving
 * any more bytes; the next FEND-bracketed frame overwrites the buffer.
 *
 * Framing errors (returns -1):
 *   * FESC followed by anything other than TFEND / TFESC.
 *   * Buffer overflow (buf_len would exceed KISS_MAX_FRAME).
 * The state is cleared on either error so the next FEND restarts cleanly.
 *
 * Constants (KISS spec):
 *   FEND = 0xC0,  FESC = 0xDB,  TFEND = 0xDC,  TFESC = 0xDD
 */

        .include "config.S"

        .equ FEND,   0xC0
        .equ FESC,   0xDB
        .equ TFEND,  0xDC
        .equ TFESC,  0xDD

        .section .text.kiss_decode_byte, "ax", @progbits
        .global kiss_decode_byte
        .type   kiss_decode_byte, @function
kiss_decode_byte:
        andi    a0, a0, 0xFF            /* normalise to 8 bits           */
        la      t0, kiss_in_frame       /* base of state block            */

        /* Branch on byte == FEND first; FEND restarts/completes a frame
         * regardless of any other state. */
        li      t6, FEND
        bne     a0, t6, .Lnot_fend

        /* FEND: complete iff in_frame && buf_len > 0; else just enter
         * frame-start state with everything cleared. */
        lbu     t1, 0(t0)               /* in_frame                      */
        beqz    t1, .Lstart_frame
        la      t2, kiss_buf_len
        lw      t3, 0(t2)
        beqz    t3, .Lstart_frame       /* in_frame but empty: restart   */
        /* Frame complete: leave buf_len + buf intact, but reset in_frame
         * so the next byte (until another FEND) is ignored. */
        sb      zero, 0(t0)
        sb      zero, 1(t0)
        sb      zero, 2(t0)
        li      a0, 1
        ret

.Lstart_frame:
        li      t1, 1
        sb      t1, 0(t0)               /* in_frame = 1                  */
        sb      zero, 1(t0)             /* escaped = 0                   */
        sb      zero, 2(t0)             /* saw_type = 0                  */
        la      t2, kiss_buf_len
        sw      zero, 0(t2)
        li      a0, 0
        ret

.Lnot_fend:
        /* If !in_frame, ignore the byte. */
        lbu     t1, 0(t0)               /* in_frame                      */
        beqz    t1, .Lreturn_zero

        /* If !saw_type, this byte is the KISS type/command — consume. */
        lbu     t2, 2(t0)               /* saw_type                      */
        bnez    t2, .Lhave_type
        li      t3, 1
        sb      t3, 2(t0)               /* saw_type = 1                  */
        li      a0, 0
        ret

.Lhave_type:
        /* If escaped, the byte must be TFEND or TFESC; substitute and
         * append, clearing the escape flag. */
        lbu     t3, 1(t0)               /* escaped                       */
        beqz    t3, .Lnot_escaped

        sb      zero, 1(t0)             /* escaped = 0                   */
        li      t4, TFEND
        beq     a0, t4, .Lappend_fend
        li      t4, TFESC
        beq     a0, t4, .Lappend_fesc
        /* Bad escape — framing error. */
        j       .Lerror

.Lappend_fend:
        li      a0, FEND
        j       .Lappend
.Lappend_fesc:
        li      a0, FESC
        j       .Lappend

.Lnot_escaped:
        /* FESC starts an escape sequence — set escaped, return. */
        li      t4, FESC
        bne     a0, t4, .Lappend
        li      t5, 1
        sb      t5, 1(t0)               /* escaped = 1                   */
        li      a0, 0
        ret

.Lappend:
        /* Append a0 to kiss_buf[buf_len]; bounds-check against
         * KISS_MAX_FRAME and increment buf_len. */
        la      t2, kiss_buf_len
        lw      t3, 0(t2)
        li      t4, KISS_MAX_FRAME
        bge     t3, t4, .Lerror
        la      t5, kiss_buf
        add     t5, t5, t3
        sb      a0, 0(t5)
        addi    t3, t3, 1
        sw      t3, 0(t2)
.Lreturn_zero:
        li      a0, 0
        ret

.Lerror:
        /* Reset state inline (don't tail-call kiss_decode_reset to keep
         * this leaf-and-no-spill). */
        sb      zero, 0(t0)
        sb      zero, 1(t0)
        sb      zero, 2(t0)
        la      t2, kiss_buf_len
        sw      zero, 0(t2)
        li      a0, -1
        ret

        .size   kiss_decode_byte, . - kiss_decode_byte
