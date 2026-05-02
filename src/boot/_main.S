# ============================================================================
# @function:    _main
# @module:      boot
# @inputs:      (none; entered from _reset)
# @outputs:     (does not return; runs the KISS → packet bridge)
# @clobbers:    a0, a1, a2, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       16
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-1 §boot
# @verify:      kat-only; integration via tests/boot/test__main.py
# @tests:       tests/boot/test__main.py
# @adrs:        0001, 0004, 0008
# @status:      verified
# ============================================================================

/* Bring-up + main event loop:
 *
 *   1. _init_bss / _init_data / clock_init / uart_init / log_init
 *   2. log_event("boot\\tready")
 *   3. Loop:
 *        byte   = uart_rx_byte();
 *        status = kiss_decode_byte(byte);
 *        if status == 1:                    // frame complete
 *            log_event("kiss\\trx_frame");
 *            ok = packet_parse_header(kiss_buf, kiss_buf_len, packet_struct);
 *            if ok == 0: log_event("packet\\tparsed");
 *            else:        log_event("packet\\trejected");
 *        if status < 0:
 *            log_event("kiss\\trx_error");
 *
 * The loop never exits — milestone 1's main loop is the simplest
 * possible scheduler. A real scheduler arrives in a later milestone.
 */

        .include "packet.S"

        .section .rodata.boot_event_tags, "a"
.Lboot_ready_tag:
        .ascii "boot\tready"
.Lboot_ready_tag_end:
        .equ   .Lboot_ready_tag_len, .Lboot_ready_tag_end - .Lboot_ready_tag
.Lkiss_rx_tag:
        .ascii "kiss\trx_frame"
.Lkiss_rx_tag_end:
        .equ   .Lkiss_rx_tag_len, .Lkiss_rx_tag_end - .Lkiss_rx_tag
.Lkiss_err_tag:
        .ascii "kiss\trx_error"
.Lkiss_err_tag_end:
        .equ   .Lkiss_err_tag_len, .Lkiss_err_tag_end - .Lkiss_err_tag
.Lpkt_ok_tag:
        .ascii "packet\tparsed"
.Lpkt_ok_tag_end:
        .equ   .Lpkt_ok_tag_len, .Lpkt_ok_tag_end - .Lpkt_ok_tag
.Lpkt_bad_tag:
        .ascii "packet\trejected"
.Lpkt_bad_tag_end:
        .equ   .Lpkt_bad_tag_len, .Lpkt_bad_tag_end - .Lpkt_bad_tag

        .section .text._main, "ax", @progbits
        .global _main
        .type   _main, @function
_main:
        addi    sp, sp, -16
        sw      ra, 12(sp)

        call    _init_bss
        call    _init_data
        call    clock_init
        call    uart_init
        call    log_init

        la      a0, .Lboot_ready_tag
        li      a1, .Lboot_ready_tag_len
        call    log_event

.Lloop:
        call    uart_rx_byte            /* a0 = next byte                */
        call    kiss_decode_byte        /* a0 = 0 | 1 | -1               */
        bgtz    a0, .Lframe
        bltz    a0, .Lkiss_err
        j       .Lloop

.Lframe:
        la      a0, .Lkiss_rx_tag
        li      a1, .Lkiss_rx_tag_len
        call    log_event

        la      a0, kiss_buf
        la      t0, kiss_buf_len
        lw      a1, 0(t0)
        la      a2, packet_struct
        call    packet_parse_header
        bnez    a0, .Lpkt_bad

        la      a0, .Lpkt_ok_tag
        li      a1, .Lpkt_ok_tag_len
        call    log_event
        j       .Lloop

.Lpkt_bad:
        la      a0, .Lpkt_bad_tag
        li      a1, .Lpkt_bad_tag_len
        call    log_event
        j       .Lloop

.Lkiss_err:
        la      a0, .Lkiss_err_tag
        li      a1, .Lkiss_err_tag_len
        call    log_event
        j       .Lloop

        .size   _main, . - _main
