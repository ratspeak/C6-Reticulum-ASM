# ============================================================================
# @function:    _main
# @module:      boot
# @inputs:      (none; entered from _reset)
# @outputs:     (does not return; emits boot.ready then runs the KISS bridge)
# @clobbers:    a0, a1, t0..t6, ra
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

/* Bring-up sequence:
 *   1. _init_bss / _init_data / clock_init / uart_init / log_init
 *   2. log_event("boot\\tready") — first observable line
 *   3. KISS bridge loop:
 *        byte   = uart_rx_byte();
 *        status = kiss_decode_byte(byte);
 *        if (status > 0) log_event("kiss\\trx_frame");
 *        else if (status < 0) log_event("kiss\\trx_error");
 *
 * Field-bearing log lines (e.g. len=N, dest=…) require log_event API
 * extension; they land when packet_parse_header arrives and there is
 * structured data to report.
 */

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

        /* KISS bridge loop. */
.Lloop:
        call    uart_rx_byte            /* a0 = next byte                */
        call    kiss_decode_byte        /* a0 = 0 | 1 | -1               */
        bgtz    a0, .Lframe
        bltz    a0, .Lerror
        j       .Lloop
.Lframe:
        la      a0, .Lkiss_rx_tag
        li      a1, .Lkiss_rx_tag_len
        call    log_event
        j       .Lloop
.Lerror:
        la      a0, .Lkiss_err_tag
        li      a1, .Lkiss_err_tag_len
        call    log_event
        j       .Lloop

        .size   _main, . - _main
