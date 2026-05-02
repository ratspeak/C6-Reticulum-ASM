# ============================================================================
# @function:    kiss_encode_frame
# @module:      kiss
# @inputs:      a0 = src ptr, a1 = src len, a2 = dst ptr, a3 = dst capacity
# @outputs:     a0 = bytes written to dst, OR -1 on overflow (dst too small)
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~10 + 2 per src byte + escapes)
# @ct:          not-required
# @spec:        KISS spec (Karn 1986); milestone-1 §kiss
# @verify:      kat-only; differential test against tests/harness/oracle.py:kiss_encode
# @tests:       tests/kiss/test_kiss_encode_frame.py
# @adrs:        0002
# @status:      verified
# ============================================================================

/* Frame `src` (a0, a1) into KISS form in the caller-provided `dst`
 * buffer (a2, a3 = capacity). Output layout:
 *   [FEND] [type=0] [escaped src bytes...] [FEND]
 *
 * Returns the number of bytes written, or -1 if the dst capacity is
 * insufficient. The bound is `2 + 2*src_len + 1` worst-case (every src
 * byte is FEND or FESC and gets escaped), so a 1024-byte src needs
 * 2051 bytes of dst.
 *
 * No allocation, no globals modified — pure data transformation in/out
 * of caller buffers. Per ADR-0002.
 */

        .equ FEND,   0xC0
        .equ FESC,   0xDB
        .equ TFEND,  0xDC
        .equ TFESC,  0xDD

        .section .text.kiss_encode_frame, "ax", @progbits
        .global kiss_encode_frame
        .type   kiss_encode_frame, @function
kiss_encode_frame:
        /* Capacity sanity: need at least 3 bytes (FEND + type + FEND). */
        li      t0, 3
        blt     a3, t0, .Lkef_overflow

        mv      t0, a2                  /* write cursor                  */
        add     t1, a2, a3              /* dst end (exclusive)           */

        li      t2, FEND
        sb      t2, 0(t0)
        addi    t0, t0, 1
        sb      zero, 0(t0)             /* type = 0 (data frame)         */
        addi    t0, t0, 1

        /* Body loop: for each src byte, emit either the byte verbatim
         * or the 2-byte escape pair. */
        mv      t3, a0                  /* src cursor                    */
        add     t4, a0, a1              /* src end                       */

.Lkef_loop:
        beq     t3, t4, .Lkef_close
        lbu     t5, 0(t3)
        addi    t3, t3, 1

        li      t6, FEND
        beq     t5, t6, .Lkef_esc_fend
        li      t6, FESC
        beq     t5, t6, .Lkef_esc_fesc

        /* Plain byte. Need 1 more dst slot (plus the closing FEND, so
         * 2 total before we may write). */
        addi    t6, t0, 2
        bgt     t6, t1, .Lkef_overflow
        sb      t5, 0(t0)
        addi    t0, t0, 1
        j       .Lkef_loop

.Lkef_esc_fend:
        addi    t6, t0, 3               /* need 2 + closing FEND         */
        bgt     t6, t1, .Lkef_overflow
        li      t5, FESC
        sb      t5, 0(t0)
        addi    t0, t0, 1
        li      t5, TFEND
        sb      t5, 0(t0)
        addi    t0, t0, 1
        j       .Lkef_loop

.Lkef_esc_fesc:
        addi    t6, t0, 3
        bgt     t6, t1, .Lkef_overflow
        li      t5, FESC
        sb      t5, 0(t0)
        addi    t0, t0, 1
        li      t5, TFESC
        sb      t5, 0(t0)
        addi    t0, t0, 1
        j       .Lkef_loop

.Lkef_close:
        li      t5, FEND
        sb      t5, 0(t0)
        addi    t0, t0, 1
        sub     a0, t0, a2              /* bytes written                 */
        ret

.Lkef_overflow:
        li      a0, -1
        ret

        .size   kiss_encode_frame, . - kiss_encode_frame
