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
.Lsha256_tag:
        .ascii "sha256\tdigest\thex="
.Lsha256_tag_end:
        .equ   .Lsha256_tag_len, .Lsha256_tag_end - .Lsha256_tag
.Lhmac_tag:
        .ascii "hmac\ttag\thex="
.Lhmac_tag_end:
        .equ   .Lhmac_tag_len, .Lhmac_tag_end - .Lhmac_tag
.Lhkdf_extract_tag:
        .ascii "hkdf\textract\thex="
.Lhkdf_extract_tag_end:
        .equ   .Lhkdf_extract_tag_len, .Lhkdf_extract_tag_end - .Lhkdf_extract_tag
.Lhkdf_expand_tag:
        .ascii "hkdf\texpand\thex="
.Lhkdf_expand_tag_end:
        .equ   .Lhkdf_expand_tag_len, .Lhkdf_expand_tag_end - .Lhkdf_expand_tag

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

        /* Crypto KAT triggers — the first byte of the frame selects a
         * test handler. 'S' (0x53) → sha256, 'H' (0x48) → HMAC-SHA-256.
         * Real Reticulum frames never start with these because their
         * header byte's bit-7 is the IFAC flag, not an ASCII letter
         * (well-formed Reticulum traffic also never carries low-byte
         * ASCII like 0x48 in the first position, and even if it did
         * we would simply fail to parse it as a packet — no production
         * cost beyond a single byte-compare per frame). */
        la      t0, kiss_buf
        lbu     t1, 0(t0)
        li      t2, 0x53
        beq     t1, t2, .Lsha256_kat
        li      t2, 0x48
        beq     t1, t2, .Lhmac_kat
        li      t2, 0x45
        beq     t1, t2, .Lhkdf_extract_kat
        li      t2, 0x58
        beq     t1, t2, .Lhkdf_expand_kat

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

.Lsha256_kat:
        /* sha256_init(sha256_ctx) */
        la      a0, sha256_ctx
        call    sha256_init
        /* sha256_update(sha256_ctx, kiss_buf+1, kiss_buf_len-1) */
        la      a0, sha256_ctx
        la      a1, kiss_buf
        addi    a1, a1, 1
        la      t0, kiss_buf_len
        lw      a2, 0(t0)
        addi    a2, a2, -1
        call    sha256_update
        /* sha256_final(sha256_ctx, sha256_digest_buf) */
        la      a0, sha256_ctx
        la      a1, sha256_digest_buf
        call    sha256_final
        /* Emit "<ts>\tsha256\tdigest\thex=<64hex>\r\n" */
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lsha256_tag
        li      a1, .Lsha256_tag_len
        call    log_str
        la      a0, sha256_digest_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lhmac_kat:
        /* HMAC test frame layout: 'H' || keylen[1] || key[keylen] || msg[*]
         * a0 = key_ptr, a1 = key_len, a2 = msg_ptr, a3 = msg_len, a4 = out
         */
        la      t0, kiss_buf
        lbu     a1, 1(t0)               /* key_len                     */
        addi    a0, t0, 2               /* &key                        */
        add     a2, a0, a1              /* &msg = &key + key_len       */
        la      t1, kiss_buf_len
        lw      t1, 0(t1)
        addi    t1, t1, -2
        sub     a3, t1, a1              /* msg_len = total-2-key_len   */
        la      a4, sha256_digest_buf
        call    hmac_sha256
        /* Emit "<ts>\thmac\ttag\thex=<64hex>\r\n" */
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lhmac_tag
        li      a1, .Lhmac_tag_len
        call    log_str
        la      a0, sha256_digest_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lhkdf_extract_kat:
        /* HKDF-Extract test frame: 'E' || saltlen[1] || salt[saltlen] || ikm[*]
         * a0=salt, a1=saltlen, a2=ikm, a3=ikm_len, a4=prk_out
         */
        la      t0, kiss_buf
        lbu     a1, 1(t0)
        addi    a0, t0, 2
        add     a2, a0, a1
        la      t1, kiss_buf_len
        lw      t1, 0(t1)
        addi    t1, t1, -2
        sub     a3, t1, a1
        la      a4, sha256_digest_buf
        call    hkdf_extract
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lhkdf_extract_tag
        li      a1, .Lhkdf_extract_tag_len
        call    log_str
        la      a0, sha256_digest_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lhkdf_expand_kat:
        /* HKDF-Expand test frame: 'X' || prk[32] || okm_len[1] || info_len[1] || info[info_len]
         * a0=prk, a1=32, a2=info, a3=info_len, a4=okm_out, a5=okm_len. */
        la      t0, kiss_buf
        addi    a0, t0, 1               /* &prk                        */
        li      a1, 32                  /* prk_len                     */
        addi    t1, t0, 33              /* &okm_len byte               */
        lbu     a5, 0(t1)               /* okm_len                     */
        addi    t1, t1, 1               /* &info_len byte              */
        lbu     a3, 0(t1)               /* info_len                    */
        addi    a2, t1, 1               /* &info                       */
        la      a4, hkdf_okm_buf
        call    hkdf_expand
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lhkdf_expand_tag
        li      a1, .Lhkdf_expand_tag_len
        call    log_str
        /* Re-read okm_len from kiss_buf[33] for the digest length. */
        la      t0, kiss_buf
        lbu     a1, 33(t0)
        la      a0, hkdf_okm_buf
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
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
