# ============================================================================
# @function:    ed25519_verify
# @module:      crypto/ed25519
# @inputs:      a0 = sig ptr   (64 bytes; R || s)
#               a1 = msg_ptr
#               a2 = msg_len
#               a3 = pk ptr    (32 bytes; encoded public key)
# @outputs:     a0 (return value): 0 if signature is valid, 1 otherwise.
# @clobbers:    t0..t6, a4..a7, s0..s4
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       768
# @cycles:      bounded (≈ 2 decompress + 2 scalarmult + 1 sha512 +
#               sc_reduce + 1 point_add + 1 compress ≈ 22M)
# @ct:          required (data-dependent only on the public sig + pk + M;
#               the validity outcome is itself public)
# @spec:        RFC 8032 §5.1.7 — Ed25519 verification (non-cofactored).
#                 1. A := decompress(pk_bytes); fail if invalid
#                 2. R := decompress(sig[0..31]); fail if invalid
#                 3. k := SHA-512(R_bytes || pk_bytes || M) reduced mod L
#                 4. result := s · B  -  k · A  (variable-base scalarmult
#                                                via the same shared
#                                                ed25519_scalarmult)
#                 5. compare compress(result) to sig[0..31]; equal ⇒ 0,
#                    else 1.
# @verify:      kat-only; QEMU pytest verifies a battery of (sk, msg)
#               sign-then-verify round-trips (assert verify == 0) plus
#               negative cases (tampered sig / pk / msg → verify == 1).
# @tests:       tests/crypto/ed25519/test_ed25519_verify.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (768 bytes, 16-byte aligned):
 *      0..159    A_point     (decompressed pk)
 *    160..319    R_point     (decompressed sig[0..31])
 *    320..479    RESULT_POINT (s·B  → s·B − k·A)
 *    480..639    TEMP_POINT  (k·A  → −k·A)
 *    640..671    K_BUF       (scalar k, reduced mod L)
 *    672..703    CHECKSUM_BUF (32-byte compressed result)
 *    704..735    pad
 *    736..739    s4
 *    740..743    s3
 *    744..747    s2
 *    748..751    s1
 *    752..755    s0
 *    756..759    ra
 *    760..767    pad
 */

        .include "x25519.S"
        .include "ed25519.S"
        .include "sha512.S"

        .equ A_OFF,         0
        .equ R_OFF,       160
        .equ RESULT_OFF,  320
        .equ TEMP_OFF,    480
        .equ K_OFF,       640
        .equ CHK_OFF,     672
        .equ S4_OFF,      736
        .equ S3_OFF,      740
        .equ S2_OFF,      744
        .equ S1_OFF,      748
        .equ S0_OFF,      752
        .equ RA_OFF,      756
        .equ FRAME,       768

        .equ PT_X, 0
        .equ PT_T, 120

        .section .text.ed25519_verify, "ax", @progbits
        .global ed25519_verify
        .type   ed25519_verify, @function
ed25519_verify:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)

        mv      s0, a0                          /* sig_ptr                */
        mv      s2, a1                          /* msg_ptr                */
        mv      s3, a2                          /* msg_len                */
        mv      s1, a3                          /* pk_ptr                 */
        li      s4, 1                           /* default: invalid       */

        # 1. A_point := decompress(pk_bytes)
        addi    a0, sp, A_OFF
        mv      a1, s1
        call    ed25519_point_decompress
        bnez    a0, .Lverify_done

        # 2. R_point := decompress(sig[0..31])
        addi    a0, sp, R_OFF
        mv      a1, s0
        call    ed25519_point_decompress
        bnez    a0, .Lverify_done

        # 3. k := reduce(SHA-512(R_bytes || pk_bytes || msg))
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        mv      a1, s0                          /* R bytes (sig[0..31])   */
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        mv      a1, s1                          /* pk bytes               */
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        mv      a1, s2                          /* msg                    */
        mv      a2, s3
        call    sha512_update
        la      a0, sha512_ctx
        la      a1, sha512_digest_buf
        call    sha512_final
        addi    a0, sp, K_OFF
        la      a1, sha512_digest_buf
        call    ed25519_sc_reduce

        # 4. RESULT_POINT := s · B
        addi    a0, sp, RESULT_OFF
        addi    a1, s0, 32                       /* &s = sig[32..63]      */
        la      a2, ed25519_base_point
        call    ed25519_scalarmult

        # 5. TEMP_POINT := k · A
        addi    a0, sp, TEMP_OFF
        addi    a1, sp, K_OFF
        addi    a2, sp, A_OFF
        call    ed25519_scalarmult

        # 6. Negate TEMP_POINT (X := -X, T := -T). Use CHK_BUF as a
        #    transient zero source for the field_sub.
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
        sw      zero, (\i + CHK_OFF)(sp)
        .endr
        addi    a0, sp, TEMP_OFF + PT_X
        addi    a1, sp, CHK_OFF
        addi    a2, sp, TEMP_OFF + PT_X
        call    x25519_field_sub
        addi    a0, sp, TEMP_OFF + PT_T
        addi    a1, sp, CHK_OFF
        addi    a2, sp, TEMP_OFF + PT_T
        call    x25519_field_sub

        # 7. RESULT_POINT := RESULT_POINT + TEMP_POINT  (= s·B − k·A)
        addi    a0, sp, RESULT_OFF
        addi    a1, sp, RESULT_OFF
        addi    a2, sp, TEMP_OFF
        call    ed25519_point_add

        # 8. checksum := compress(RESULT_POINT)
        addi    a0, sp, CHK_OFF
        addi    a1, sp, RESULT_OFF
        call    ed25519_point_compress

        # 9. Compare checksum to sig[0..31] word-by-word. Mismatch ⇒
        #    keep s4 = 1; full match ⇒ s4 = 0.
        addi    t3, sp, CHK_OFF
        mv      t4, s0
        li      t5, 0                            /* accumulator           */
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, \i(t3)
        lw      t1, \i(t4)
        xor     t2, t0, t1
        or      t5, t5, t2
        .endr
        # If t5 != 0, keep invalid (s4 = 1). If t5 == 0, set s4 = 0.
        bnez    t5, .Lverify_done
        li      s4, 0

.Lverify_done:
        mv      a0, s4
        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_verify, . - ed25519_verify
