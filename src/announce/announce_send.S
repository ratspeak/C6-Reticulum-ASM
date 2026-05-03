# ============================================================================
# @function:    announce_send
# @module:      announce
# @inputs:      a0 = identity_t*, a1 = name_hash ptr (10 bytes), a2 = app_data ptr (may be 0 when app_data_len = 0), a3 = app_data_len
# @outputs:     a0 = raw announce length on success, negative errno on failure
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       64
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-3 announce_send; KISS-framed Reticulum announce TX path
# @verify:      proofs/announce/announce_tx.tla
# @tests:       tests/announce/test_announce_send.py
# @adrs:        0001, 0002, 0004, 0006, 0009
# @status:      verified
# ============================================================================

/* Build a raw HEADER_1 announce into static storage, KISS-frame it, emit the
 * milestone-3 trace lines, and transmit the KISS frame on UART.
 *
 * Trace lines:
 *   <ts8hex>\tannounce\tbuilt\tlen=<raw_len>\r\n
 *   <ts8hex>\tkiss\ttx_frame\tlen=<kiss_len>\r\n
 *
 * The length formatter is deliberately tiny: valid raw/KISS lengths are below
 * 1000 because Reticulum MDU is 484 and KISS worst-case capacity is 971.
 * Secret-key constant-time behavior is owned by announce_build and crypto
 * callees; the post-build KISS/UART path handles only public bytes.
 */

        .include "announce.S"

        .equ AS_S0_OFF,   0
        .equ AS_S1_OFF,   4
        .equ AS_S2_OFF,   8
        .equ AS_S3_OFF,   12
        .equ AS_S4_OFF,   16
        .equ AS_S5_OFF,   20
        .equ AS_S6_OFF,   24
        .equ AS_S7_OFF,   28
        .equ AS_S8_OFF,   32
        .equ AS_S9_OFF,   36
        .equ AS_S10_OFF,  40
        .equ AS_S11_OFF,  44
        .equ AS_RA_OFF,   60
        .equ AS_FRAME,    64
        .equ AS_LOG_BUILT_PREFIX_LEN, 19
        .equ AS_LOG_KISS_PREFIX_LEN,  18

        .section .text.announce_send, "ax", @progbits
        .global announce_send
        .type   announce_send, @function
announce_send:
        addi    sp, sp, -AS_FRAME
        sw      s0, AS_S0_OFF(sp)
        sw      s1, AS_S1_OFF(sp)
        sw      s2, AS_S2_OFF(sp)
        sw      s3, AS_S3_OFF(sp)
        sw      s4, AS_S4_OFF(sp)
        sw      s5, AS_S5_OFF(sp)
        sw      s6, AS_S6_OFF(sp)
        sw      s7, AS_S7_OFF(sp)
        sw      s8, AS_S8_OFF(sp)
        sw      s9, AS_S9_OFF(sp)
        sw      s10, AS_S10_OFF(sp)
        sw      s11, AS_S11_OFF(sp)
        sw      ra, AS_RA_OFF(sp)

        mv      s0, a0                  /* identity_t*                  */
        mv      s1, a1                  /* name_hash ptr                */
        mv      s2, a2                  /* app_data ptr                 */
        mv      s3, a3                  /* app_data_len                 */

        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        mv      a3, s3
        la      a4, announce_raw_tx_buf
        li      a5, ANNOUNCE_RETICULUM_MDU
        call    announce_build
        blt     a0, zero, .Las_return
        mv      s4, a0                  /* raw announce length          */

        la      a0, announce_raw_tx_buf
        mv      a1, s4
        la      a2, announce_kiss_tx_buf
        li      a3, ANNOUNCE_KISS_TX_CAPACITY
        call    kiss_encode_frame
        blt     a0, zero, .Las_return
        mv      s5, a0                  /* KISS frame length            */

        la      a0, .Las_log_built_prefix
        li      a1, AS_LOG_BUILT_PREFIX_LEN
        mv      a2, s4
        call    .Las_emit_len_event

        la      a0, .Las_log_kiss_prefix
        li      a1, AS_LOG_KISS_PREFIX_LEN
        mv      a2, s5
        call    .Las_emit_len_event

        la      a0, announce_kiss_tx_buf
        mv      a1, s5
        call    uart_tx_bytes

        mv      a0, s4

.Las_return:
        lw      s0, AS_S0_OFF(sp)
        lw      s1, AS_S1_OFF(sp)
        lw      s2, AS_S2_OFF(sp)
        lw      s3, AS_S3_OFF(sp)
        lw      s4, AS_S4_OFF(sp)
        lw      s5, AS_S5_OFF(sp)
        lw      s6, AS_S6_OFF(sp)
        lw      s7, AS_S7_OFF(sp)
        lw      s8, AS_S8_OFF(sp)
        lw      s9, AS_S9_OFF(sp)
        lw      s10, AS_S10_OFF(sp)
        lw      s11, AS_S11_OFF(sp)
        lw      ra, AS_RA_OFF(sp)
        addi    sp, sp, AS_FRAME
        ret

.Las_emit_len_event:
        mv      s9, ra                  /* return to announce_send      */
        mv      s6, a0                  /* prefix ptr                   */
        mv      s7, a1                  /* prefix len                   */
        mv      s8, a2                  /* numeric len                  */

        call    clock_now_ms
        li      a1, 8
        call    log_hex

        li      a0, 9                   /* '\t'                         */
        call    uart_tx_byte

        mv      a0, s6
        mv      a1, s7
        call    uart_tx_bytes

        mv      a0, s8
        call    .Las_emit_u32_dec_3

        li      a0, 13                  /* '\r'                         */
        call    uart_tx_byte
        li      a0, 10                  /* '\n'                         */
        call    uart_tx_byte

        jr      s9

.Las_emit_u32_dec_3:
        mv      s10, ra
        li      t0, 100
        divu    s6, a0, t0              /* hundreds                     */
        remu    t1, a0, t0
        li      t0, 10
        divu    s7, t1, t0              /* tens                         */
        remu    s8, t1, t0              /* ones                         */

        beqz    s6, .Las_dec_no_hundreds
        addi    a0, s6, 48
        call    uart_tx_byte
        j       .Las_dec_emit_tens

.Las_dec_no_hundreds:
        beqz    s7, .Las_dec_emit_ones

.Las_dec_emit_tens:
        addi    a0, s7, 48
        call    uart_tx_byte

.Las_dec_emit_ones:
        addi    a0, s8, 48
        call    uart_tx_byte
        jr      s10

        .size   announce_send, . - announce_send

        .section .rodata.announce_send, "a", @progbits
.Las_log_built_prefix:
        .ascii  "announce\tbuilt\tlen="
.Las_log_built_prefix_end:

.Las_log_kiss_prefix:
        .ascii  "kiss\ttx_frame\tlen="
.Las_log_kiss_prefix_end:
