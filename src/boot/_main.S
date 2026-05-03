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
        .include "aes.S"

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
.Lsha512_tag:
        .ascii "sha512\tdigest\thex="
.Lsha512_tag_end:
        .equ   .Lsha512_tag_len, .Lsha512_tag_end - .Lsha512_tag
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
.Laes_sbox_tag:
        .ascii "aes\tsbox\thex="
.Laes_sbox_tag_end:
        .equ   .Laes_sbox_tag_len, .Laes_sbox_tag_end - .Laes_sbox_tag
.Laes_invsbox_tag:
        .ascii "aes\tinvsbox\thex="
.Laes_invsbox_tag_end:
        .equ   .Laes_invsbox_tag_len, .Laes_invsbox_tag_end - .Laes_invsbox_tag
.Laes_mc_tag:
        .ascii "aes\tmixcolumns\thex="
.Laes_mc_tag_end:
        .equ   .Laes_mc_tag_len, .Laes_mc_tag_end - .Laes_mc_tag
.Laes_imc_tag:
        .ascii "aes\tinvmixcolumns\thex="
.Laes_imc_tag_end:
        .equ   .Laes_imc_tag_len, .Laes_imc_tag_end - .Laes_imc_tag
.Laes_ke_tag:
        .ascii "aes\tkey_expand\thex="
.Laes_ke_tag_end:
        .equ   .Laes_ke_tag_len, .Laes_ke_tag_end - .Laes_ke_tag
.Laes_enc_tag:
        .ascii "aes\tencrypt\thex="
.Laes_enc_tag_end:
        .equ   .Laes_enc_tag_len, .Laes_enc_tag_end - .Laes_enc_tag
.Laes_dec_tag:
        .ascii "aes\tdecrypt\thex="
.Laes_dec_tag_end:
        .equ   .Laes_dec_tag_len, .Laes_dec_tag_end - .Laes_dec_tag
.Laes_cbc_enc_tag:
        .ascii "aes\tcbc_encrypt\thex="
.Laes_cbc_enc_tag_end:
        .equ   .Laes_cbc_enc_tag_len, .Laes_cbc_enc_tag_end - .Laes_cbc_enc_tag
.Laes_cbc_dec_tag:
        .ascii "aes\tcbc_decrypt\thex="
.Laes_cbc_dec_tag_end:
        .equ   .Laes_cbc_dec_tag_len, .Laes_cbc_dec_tag_end - .Laes_cbc_dec_tag
.Lx25519_fmul_tag:
        .ascii "x25519\tfield_mul\thex="
.Lx25519_fmul_tag_end:
        .equ   .Lx25519_fmul_tag_len, .Lx25519_fmul_tag_end - .Lx25519_fmul_tag
.Lx25519_fsq_tag:
        .ascii "x25519\tfield_sq\thex="
.Lx25519_fsq_tag_end:
        .equ   .Lx25519_fsq_tag_len, .Lx25519_fsq_tag_end - .Lx25519_fsq_tag
.Lx25519_finv_tag:
        .ascii "x25519\tfield_inv\thex="
.Lx25519_finv_tag_end:
        .equ   .Lx25519_finv_tag_len, .Lx25519_finv_tag_end - .Lx25519_finv_tag
.Lx25519_ladder_tag:
        .ascii "x25519\tladder\thex="
.Lx25519_ladder_tag_end:
        .equ   .Lx25519_ladder_tag_len, .Lx25519_ladder_tag_end - .Lx25519_ladder_tag
.Lx25519_smult_tag:
        .ascii "x25519\tscalar_mult\thex="
.Lx25519_smult_tag_end:
        .equ   .Lx25519_smult_tag_len, .Lx25519_smult_tag_end - .Lx25519_smult_tag
.Lrng_tag:
        .ascii "rng\tbytes\thex="
.Lrng_tag_end:
        .equ   .Lrng_tag_len, .Lrng_tag_end - .Lrng_tag
.Lx25519_kp_pk_tag:
        .ascii "x25519\tkeypair_pk\thex="
.Lx25519_kp_pk_tag_end:
        .equ   .Lx25519_kp_pk_tag_len, .Lx25519_kp_pk_tag_end - .Lx25519_kp_pk_tag
.Lx25519_kp_sk_tag:
        .ascii "x25519\tkeypair_sk\thex="
.Lx25519_kp_sk_tag_end:
        .equ   .Lx25519_kp_sk_tag_len, .Lx25519_kp_sk_tag_end - .Lx25519_kp_sk_tag
.Led25519_sc_red_tag:
        .ascii "ed25519\tsc_reduce\thex="
.Led25519_sc_red_tag_end:
        .equ   .Led25519_sc_red_tag_len, .Led25519_sc_red_tag_end - .Led25519_sc_red_tag
.Led25519_sc_madd_tag:
        .ascii "ed25519\tsc_muladd\thex="
.Led25519_sc_madd_tag_end:
        .equ   .Led25519_sc_madd_tag_len, .Led25519_sc_madd_tag_end - .Led25519_sc_madd_tag
.Led25519_kp_sk_tag:
        .ascii "ed25519\tkeypair_sk\thex="
.Led25519_kp_sk_tag_end:
        .equ   .Led25519_kp_sk_tag_len, .Led25519_kp_sk_tag_end - .Led25519_kp_sk_tag
.Led25519_kp_pk_tag:
        .ascii "ed25519\tkeypair_pk\thex="
.Led25519_kp_pk_tag_end:
        .equ   .Led25519_kp_pk_tag_len, .Led25519_kp_pk_tag_end - .Led25519_kp_pk_tag
.Led25519_sign_tag:
        .ascii "ed25519\tsign\thex="
.Led25519_sign_tag_end:
        .equ   .Led25519_sign_tag_len, .Led25519_sign_tag_end - .Led25519_sign_tag
.Led25519_verify_tag:
        .ascii "ed25519\tverify\thex="
.Led25519_verify_tag_end:
        .equ   .Led25519_verify_tag_len, .Led25519_verify_tag_end - .Led25519_verify_tag

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
        call    rng_init                /* zero deterministic counter   */

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
         * test handler. 'S' (0x53) → sha256, 'H' (0x48) → HMAC-SHA-256,
         * 'E' (0x45) → HKDF-Extract, 'X' (0x58) → HKDF-Expand,
         * 'B' (0x42) → AES-S-box (apply per-byte to the rest of the frame).
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
        li      t2, 0x68                /* 'h' for sha512                */
        beq     t1, t2, .Lsha512_kat
        li      t2, 0x48
        beq     t1, t2, .Lhmac_kat
        li      t2, 0x45
        beq     t1, t2, .Lhkdf_extract_kat
        li      t2, 0x58
        beq     t1, t2, .Lhkdf_expand_kat
        li      t2, 0x42
        beq     t1, t2, .Laes_sbox_kat
        li      t2, 0x49
        beq     t1, t2, .Laes_invsbox_kat
        li      t2, 0x4D
        beq     t1, t2, .Laes_mc_kat
        li      t2, 0x6D
        beq     t1, t2, .Laes_imc_kat
        li      t2, 0x4B
        beq     t1, t2, .Laes_ke_kat
        li      t2, 0x43
        beq     t1, t2, .Laes_enc_kat
        li      t2, 0x44
        beq     t1, t2, .Laes_dec_kat
        li      t2, 0x56
        beq     t1, t2, .Laes_cbc_enc_kat
        li      t2, 0x76
        beq     t1, t2, .Laes_cbc_dec_kat
        li      t2, 0x46
        beq     t1, t2, .Lx25519_fmul_kat
        li      t2, 0x51
        beq     t1, t2, .Lx25519_fsq_kat
        li      t2, 0x69
        beq     t1, t2, .Lx25519_finv_kat
        li      t2, 0x4C
        beq     t1, t2, .Lx25519_ladder_kat
        li      t2, 0x73                /* 's' for x25519_scalar_mult     */
        beq     t1, t2, .Lx25519_smult_kat
        li      t2, 0x72                /* 'r' for rng_bytes              */
        beq     t1, t2, .Lrng_kat
        li      t2, 0x6B                /* 'k' for x25519_keypair         */
        beq     t1, t2, .Lx25519_keypair_kat
        li      t2, 0x52                /* 'R' for ed25519_sc_reduce      */
        beq     t1, t2, .Led25519_sc_red_kat
        li      t2, 0x61                /* 'a' for ed25519_sc_muladd      */
        beq     t1, t2, .Led25519_sc_madd_kat
        li      t2, 0x67                /* 'g' for ed25519_keypair (gen)  */
        beq     t1, t2, .Led25519_keypair_kat
        li      t2, 0x47                /* 'G' for ed25519_sign           */
        beq     t1, t2, .Led25519_sign_kat
        li      t2, 0x79                /* 'y' for ed25519_verify         */
        beq     t1, t2, .Led25519_verify_kat

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

.Lsha512_kat:
        /* sha512: 'h' || data → emits 128 hex of digest. */
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        la      a1, kiss_buf
        addi    a1, a1, 1
        la      t0, kiss_buf_len
        lw      a2, 0(t0)
        addi    a2, a2, -1
        call    sha512_update
        la      a0, sha512_ctx
        la      a1, sha512_digest_buf
        call    sha512_final
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lsha512_tag
        li      a1, .Lsha512_tag_len
        call    log_str
        la      a0, sha512_digest_buf
        li      a1, 64
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

.Laes_sbox_kat:
        /* AES-S-box test frame: 'B' || byte_0 || ... || byte_(n-1).
         * Apply aes_sbox to each input byte in place. n = kiss_buf_len - 1.
         * State spans aes_sbox calls via _main's frame: 0(sp)=base, 4(sp)=n,
         * 8(sp)=idx. Slots 0..11 are free here (only ra at 12 is used). */
        la      t0, kiss_buf
        addi    t0, t0, 1
        sw      t0, 0(sp)               /* base */
        la      t0, kiss_buf_len
        lw      t0, 0(t0)
        addi    t0, t0, -1
        sw      t0, 4(sp)               /* n */
        sw      zero, 8(sp)             /* idx = 0 */
.Laes_sbox_kat_loop:
        lw      t0, 4(sp)
        lw      t1, 8(sp)
        bgeu    t1, t0, .Laes_sbox_kat_done
        lw      t2, 0(sp)
        add     t2, t2, t1
        lbu     a0, 0(t2)
        call    aes_sbox
        lw      t2, 0(sp)
        lw      t1, 8(sp)
        add     t2, t2, t1
        sb      a0, 0(t2)
        addi    t1, t1, 1
        sw      t1, 8(sp)
        j       .Laes_sbox_kat_loop
.Laes_sbox_kat_done:
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_sbox_tag
        li      a1, .Laes_sbox_tag_len
        call    log_str
        lw      a0, 0(sp)
        lw      a1, 4(sp)
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_invsbox_kat:
        /* AES-inverse-S-box: 'I' || byte_0 || ... || byte_(n-1). Same
         * loop structure as the forward S-box handler above. */
        la      t0, kiss_buf
        addi    t0, t0, 1
        sw      t0, 0(sp)
        la      t0, kiss_buf_len
        lw      t0, 0(t0)
        addi    t0, t0, -1
        sw      t0, 4(sp)
        sw      zero, 8(sp)
.Laes_invsbox_kat_loop:
        lw      t0, 4(sp)
        lw      t1, 8(sp)
        bgeu    t1, t0, .Laes_invsbox_kat_done
        lw      t2, 0(sp)
        add     t2, t2, t1
        lbu     a0, 0(t2)
        call    aes_invsbox
        lw      t2, 0(sp)
        lw      t1, 8(sp)
        add     t2, t2, t1
        sb      a0, 0(t2)
        addi    t1, t1, 1
        sw      t1, 8(sp)
        j       .Laes_invsbox_kat_loop
.Laes_invsbox_kat_done:
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_invsbox_tag
        li      a1, .Laes_invsbox_tag_len
        call    log_str
        lw      a0, 0(sp)
        lw      a1, 4(sp)
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_mc_kat:
        /* MixColumns test: 'M' || 16 bytes. Apply aes_mixcolumns to the
         * 16 bytes, emit them as 32 hex chars. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        call    aes_mixcolumns
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_mc_tag
        li      a1, .Laes_mc_tag_len
        call    log_str
        la      a0, kiss_buf
        addi    a0, a0, 1
        li      a1, 16
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_imc_kat:
        /* InvMixColumns test: 'm' || 16 bytes. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        call    aes_invmixcolumns
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_imc_tag
        li      a1, .Laes_imc_tag_len
        call    log_str
        la      a0, kiss_buf
        addi    a0, a0, 1
        li      a1, 16
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_ke_kat:
        /* AES-256 KeyExpand test: 'K' || key[32]. Emit 240-byte schedule
         * as 480 hex chars. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        la      a1, aes_round_keys
        call    aes256_key_expand
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_ke_tag
        li      a1, .Laes_ke_tag_len
        call    log_str
        la      a0, aes_round_keys
        li      a1, AES256_RK_BYTES
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_enc_kat:
        /* AES-256 encrypt test: 'C' || key[32] || plaintext[16].
         * Expand key, encrypt block in place into aes_block_buf, emit. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        la      a1, aes_round_keys
        call    aes256_key_expand
        la      a0, aes_round_keys
        la      a1, kiss_buf
        addi    a1, a1, 33              /* &plaintext (after 'C' + 32-byte key) */
        la      a2, aes_block_buf
        call    aes256_encrypt_block
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_enc_tag
        li      a1, .Laes_enc_tag_len
        call    log_str
        la      a0, aes_block_buf
        li      a1, AES_BLOCK_SIZE
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_dec_kat:
        /* AES-256 decrypt test: 'D' || key[32] || ciphertext[16]. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        la      a1, aes_round_keys
        call    aes256_key_expand
        la      a0, aes_round_keys
        la      a1, kiss_buf
        addi    a1, a1, 33
        la      a2, aes_block_buf
        call    aes256_decrypt_block
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_dec_tag
        li      a1, .Laes_dec_tag_len
        call    log_str
        la      a0, aes_block_buf
        li      a1, AES_BLOCK_SIZE
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_cbc_enc_kat:
        /* AES-256-CBC encrypt: 'V' || key[32] || iv[16] || nblocks[1] ||
         * plaintext[16*nblocks]. Encrypts in place over the plaintext. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        la      a1, aes_round_keys
        call    aes256_key_expand
        la      a0, aes_round_keys
        la      a1, kiss_buf
        addi    a1, a1, 33              /* &iv */
        la      a2, kiss_buf
        addi    a2, a2, 50              /* &plaintext (= &ciphertext, in-place) */
        la      t0, kiss_buf
        lbu     a3, 49(t0)              /* nblocks */
        slli    a3, a3, 4               /* * 16 */
        mv      a4, a2                  /* in-place */
        call    aes256_cbc_encrypt
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_cbc_enc_tag
        li      a1, .Laes_cbc_enc_tag_len
        call    log_str
        la      a0, kiss_buf
        addi    a0, a0, 50
        la      t0, kiss_buf
        lbu     a1, 49(t0)
        slli    a1, a1, 4
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Laes_cbc_dec_kat:
        /* AES-256-CBC decrypt: 'v' || key[32] || iv[16] || nblocks[1] ||
         * ciphertext[16*nblocks]. Decrypts in place. */
        la      a0, kiss_buf
        addi    a0, a0, 1
        la      a1, aes_round_keys
        call    aes256_key_expand
        la      a0, aes_round_keys
        la      a1, kiss_buf
        addi    a1, a1, 33
        la      a2, kiss_buf
        addi    a2, a2, 50
        la      t0, kiss_buf
        lbu     a3, 49(t0)
        slli    a3, a3, 4
        mv      a4, a2
        call    aes256_cbc_decrypt
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Laes_cbc_dec_tag
        li      a1, .Laes_cbc_dec_tag_len
        call    log_str
        la      a0, kiss_buf
        addi    a0, a0, 50
        la      t0, kiss_buf
        lbu     a1, 49(t0)
        slli    a1, a1, 4
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_fmul_kat:
        /* x25519_field_mul: 'F' || a_limbs[40] || b_limbs[40] →
         * emits 80 hex chars (40 little-endian bytes of out_limbs). */
        la      a0, x25519_field_buf
        la      a1, kiss_buf
        addi    a1, a1, 1               /* &a_limbs */
        addi    a2, a1, 40              /* &b_limbs */
        call    x25519_field_mul
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_fmul_tag
        li      a1, .Lx25519_fmul_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 40
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_fsq_kat:
        /* x25519_field_sq: 'Q' || a_limbs[40] →
         * emits 80 hex chars (40 little-endian bytes of out_limbs). */
        la      a0, x25519_field_buf
        la      a1, kiss_buf
        addi    a1, a1, 1
        call    x25519_field_sq
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_fsq_tag
        li      a1, .Lx25519_fsq_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 40
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_finv_kat:
        /* x25519_field_inv: 'i' || a_limbs[40] →
         * emits 80 hex chars (40 bytes of inv(a) in limb form). */
        la      a0, x25519_field_buf
        la      a1, kiss_buf
        addi    a1, a1, 1
        call    x25519_field_inv
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_finv_tag
        li      a1, .Lx25519_finv_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 40
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_ladder_kat:
        /* x25519_montgomery_ladder: 'L' || k_bytes[32] || u_limbs[40] →
         * emits 80 hex chars (40 bytes of result limbs). The driver assumes
         * k_bytes is already clamped per RFC 7748 §5 (caller's job; mirrors
         * the production scalar_mult flow which calls decode_scalar first). */
        la      a0, x25519_field_buf
        la      a1, kiss_buf
        addi    a1, a1, 1               /* &k_bytes                    */
        addi    a2, a1, 32              /* &u_limbs                    */
        call    x25519_montgomery_ladder
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_ladder_tag
        li      a1, .Lx25519_ladder_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 40
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Led25519_verify_kat:
        /* ed25519_verify: 'y' || sig[64] || pk[32] || msg[*] →
         * 1 byte (0x00 = valid, 0x01 = invalid) emitted as 2 hex chars. */
        la      t0, kiss_buf
        addi    a0, t0, 1               /* sig_ptr                        */
        addi    a1, t0, 1 + 64 + 32     /* msg_ptr (after sig + pk)       */
        la      t1, kiss_buf_len
        lw      a2, 0(t1)
        addi    a2, a2, -97             /* msg_len = total - 1 - 64 - 32  */
        addi    a3, t0, 1 + 64          /* pk_ptr                         */
        call    ed25519_verify
        # Store the return code into a 1-byte buffer for log_hex_buf.
        la      t0, kiss_buf
        sb      a0, 0(t0)               /* repurpose kiss_buf[0] = result */
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_verify_tag
        li      a1, .Led25519_verify_tag_len
        call    log_str
        la      a0, kiss_buf
        li      a1, 1
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Led25519_sign_kat:
        /* ed25519_sign: 'G' || sk[32] || msg[*] → 64-byte signature.
         * Frame layout: byte 0 = 'G', bytes 1..32 = sk, bytes 33..end = msg.
         * Output (kiss_buf+? not enough): use sha512_digest_buf[0..63] (we don't
         * need it after sign returns) plus kiss_buf+? as the writable sig area.
         * Actually use sha512_digest_buf[0..63] since it's exactly 64 bytes. */
        la      a0, sha512_digest_buf   /* sig_out (64 bytes)             */
        la      t0, kiss_buf
        addi    a1, t0, 33              /* msg_ptr (after 'G' + 32-byte sk) */
        la      t1, kiss_buf_len
        lw      a2, 0(t1)
        addi    a2, a2, -33             /* msg_len = total - 1 - 32       */
        addi    a3, t0, 1               /* sk_ptr                         */
        call    ed25519_sign
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_sign_tag
        li      a1, .Led25519_sign_tag_len
        call    log_str
        la      a0, sha512_digest_buf
        li      a1, 64
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Led25519_keypair_kat:
        /* ed25519_keypair: 'g' (no args). Resets RNG, then generates
         * a fresh (sk, pk) pair using the deterministic-fake CSPRNG.
         * Emits sk and pk on two log lines. */
        call    rng_init
        # Use kiss_buf+0..31 for sk and kiss_buf+32..63 for pk
        la      a0, kiss_buf
        addi    a1, a0, 32
        call    ed25519_keypair
        # Emit sk
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_kp_sk_tag
        li      a1, .Led25519_kp_sk_tag_len
        call    log_str
        la      a0, kiss_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        # Emit pk
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_kp_pk_tag
        li      a1, .Led25519_kp_pk_tag_len
        call    log_str
        la      a0, kiss_buf
        addi    a0, a0, 32
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Led25519_sc_madd_kat:
        /* ed25519_sc_muladd: 'a' || a[32] || b[32] || c[32] →
         * 64 hex of (a*b + c) mod L. */
        la      a0, x25519_field_buf    /* spare 40-byte buf, low 32 used */
        la      a1, kiss_buf
        addi    a1, a1, 1
        addi    a2, a1, 32
        addi    a3, a1, 64
        call    ed25519_sc_muladd
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_sc_madd_tag
        li      a1, .Led25519_sc_madd_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Led25519_sc_red_kat:
        /* ed25519_sc_reduce: 'R' || in_bytes[64] → 64 hex of scalar mod L. */
        la      a0, x25519_field_buf    /* spare 40-byte buf, low 32 used */
        la      a1, kiss_buf
        addi    a1, a1, 1
        call    ed25519_sc_reduce
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Led25519_sc_red_tag
        li      a1, .Led25519_sc_red_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_keypair_kat:
        /* x25519_keypair: 'k' (no args). Resets RNG to a deterministic
         * state then emits the resulting (sk, pk) on two log lines. */
        call    rng_init
        # Use kiss_buf+0..31 as sk_out scratch and x25519_field_buf+0..31 as pk_out.
        la      a0, x25519_field_buf
        la      a1, kiss_buf
        call    x25519_keypair
        # Emit sk
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_kp_sk_tag
        li      a1, .Lx25519_kp_sk_tag_len
        call    log_str
        la      a0, kiss_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        # Emit pk
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_kp_pk_tag
        li      a1, .Lx25519_kp_pk_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 32
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lrng_kat:
        /* rng_bytes: 'r' || count[1]. Reseeds counter via rng_init then
         * emits `count` deterministic bytes. */
        call    rng_init
        la      t0, kiss_buf
        lbu     a1, 1(t0)               /* count                       */
        la      a0, x25519_field_buf    /* spare 40-byte buf           */
        call    rng_bytes
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lrng_tag
        li      a1, .Lrng_tag_len
        call    log_str
        la      a0, x25519_field_buf
        la      t0, kiss_buf
        lbu     a1, 1(t0)               /* count again                 */
        call    log_hex_buf
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte
        j       .Lloop

.Lx25519_smult_kat:
        /* x25519_scalar_mult: 's' || k_bytes[32] || u_bytes[32] →
         * emits 64 hex chars (canonical 32-byte u-coordinate of k·P_u). */
        la      a0, x25519_field_buf    /* 40-byte buf, low 32 used      */
        la      a1, kiss_buf
        addi    a1, a1, 1               /* &k_bytes                      */
        addi    a2, a1, 32              /* &u_bytes                      */
        call    x25519_scalar_mult
        call    clock_now_ms
        li      a1, 8
        call    log_hex
        li      a0, 9
        call    uart_tx_byte
        la      a0, .Lx25519_smult_tag
        li      a1, .Lx25519_smult_tag_len
        call    log_str
        la      a0, x25519_field_buf
        li      a1, 32
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
