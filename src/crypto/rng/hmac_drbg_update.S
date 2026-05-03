# ============================================================================
# @function:    hmac_drbg_update
# @module:      crypto/rng
# @inputs:      a0 = data_ptr (may be NULL when a1 == 0)
#               a1 = data_len (bytes; ≤ HMAC_DRBG_SEED_LEN = 48)
# @outputs:     hmac_drbg_K, hmac_drbg_V mutated in place per NIST
#               SP 800-90A Rev. 1 §10.1.2.2.
# @clobbers:    a0..a7, t0..t6, ra, s0..s4
# @preserves:   sp, gp, all other callee-saved
# @stack:       32
# @cycles:      bounded (4 × hmac_sha256 if a1 > 0; 2 × hmac_sha256 otherwise)
# @ct:          required (no secret-dependent branches; a1 is non-secret —
#               either 0 [generate's backtrack-resistance update] or
#               HMAC_DRBG_SEED_LEN [instantiate/reseed])
# @spec:        NIST SP 800-90A Rev. 1 §10.1.2.2 HMAC_DRBG_Update:
#                 K = HMAC(K, V || 0x00 || provided_data)
#                 V = HMAC(K, V)
#                 if provided_data is not None:
#                   K = HMAC(K, V || 0x01 || provided_data)
#                   V = HMAC(K, V)
# @verify:      proofs/crypto/rng/HMACDRBG.cry, proofs/crypto/rng/hmac_drbg_update.saw
#               (Tier C deferred: the asm body invokes hmac_sha256 up
#               to four times — heavy crypto on the same pcode-
#               unreliable boundary as AES / X25519. Binary correctness
#               is established by transitivity through the QEMU pytest
#               rng_bytes KAT, which exercises both the empty-data and
#               full-seed regimes of this primitive against the
#               drbg_oracle Python mirror. See ADR-0009 §"Tier C path
#               forward".)
# @tests:       tests/crypto/rng/test_hmac_drbg_update.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Buffer layout in hmac_drbg_buf:
 *
 *     [0..32)    V (snapshot of hmac_drbg_V)
 *     [32]       sep byte (0x00 or 0x01)
 *     [33..81)   provided_data (up to HMAC_DRBG_SEED_LEN = 48)
 *
 * The HMAC primitive aliasing analysis (see hmac_sha256.S preamble):
 * hmac_sha256 reads its key (a0/a1) into hmac_key_prep before any
 * write to its output (a4); reads its message (a2/a3) into the
 * sha256_ctx block buffer before writing the output. So:
 *   * out_ptr == key_ptr is safe (key consumed before output written).
 *   * out_ptr == msg_ptr is safe (msg consumed by sha256_update calls
 *     before output written).
 * Both aliases are exploited below to update K and V in place.
 *
 * Stack frame (32 bytes; 16-aligned):
 *   sp + 0..3      saved s0  (data_ptr)
 *   sp + 4..7      saved s1  (data_len)
 *   sp + 8..11     saved s2  (&hmac_drbg_K)
 *   sp + 12..15    saved s3  (&hmac_drbg_V)
 *   sp + 16..19    saved s4  (&hmac_drbg_buf)
 *   sp + 20..27    pad
 *   sp + 28..31    saved ra
 */

        .include "rng.S"

        .equ DRBG_S0_OFF, 0
        .equ DRBG_S1_OFF, 4
        .equ DRBG_S2_OFF, 8
        .equ DRBG_S3_OFF, 12
        .equ DRBG_S4_OFF, 16
        .equ DRBG_RA_OFF, 28
        .equ DRBG_FRAME,  32

        .section .text.hmac_drbg_update, "ax", @progbits
        .global hmac_drbg_update
        .type   hmac_drbg_update, @function
hmac_drbg_update:
        addi    sp, sp, -DRBG_FRAME
        sw      ra, DRBG_RA_OFF(sp)
        sw      s4, DRBG_S4_OFF(sp)
        sw      s3, DRBG_S3_OFF(sp)
        sw      s2, DRBG_S2_OFF(sp)
        sw      s1, DRBG_S1_OFF(sp)
        sw      s0, DRBG_S0_OFF(sp)

        mv      s0, a0                  /* data_ptr                       */
        mv      s1, a1                  /* data_len                       */
        la      s2, hmac_drbg_K
        la      s3, hmac_drbg_V
        la      s4, hmac_drbg_buf

        /* ---- Round 1: K = HMAC(K, V || 0x00 || data) ---------------- */
        /* Build buf = V || 0x00 || data                                 */
        mv      a0, s4
        mv      a1, s3
        call    .Lcopy_v_to_buf
        sb      zero, HMAC_DRBG_SEP_OFFSET(s4)
        beqz    s1, .Lhmac1
        addi    a0, s4, HMAC_DRBG_DATA_OFFSET
        mv      a1, s0
        mv      a2, s1
        call    .Lcopy_data
.Lhmac1:
        /* hmac_sha256(K, 32, buf, 33+data_len, K) */
        mv      a0, s2
        li      a1, HMAC_DRBG_KEY_LEN
        mv      a2, s4
        addi    a3, s1, HMAC_DRBG_DATA_OFFSET
        mv      a4, s2
        call    hmac_sha256

        /* ---- Round 2: V = HMAC(K, V) -------------------------------- */
        mv      a0, s2
        li      a1, HMAC_DRBG_KEY_LEN
        mv      a2, s3
        li      a3, HMAC_DRBG_V_LEN
        mv      a4, s3
        call    hmac_sha256

        /* If data_len == 0, the update is finished. */
        beqz    s1, .Lupdate_done

        /* ---- Round 3: K = HMAC(K, V || 0x01 || data) ---------------- */
        mv      a0, s4
        mv      a1, s3
        call    .Lcopy_v_to_buf
        li      t0, 1
        sb      t0, HMAC_DRBG_SEP_OFFSET(s4)
        addi    a0, s4, HMAC_DRBG_DATA_OFFSET
        mv      a1, s0
        mv      a2, s1
        call    .Lcopy_data

        mv      a0, s2
        li      a1, HMAC_DRBG_KEY_LEN
        mv      a2, s4
        addi    a3, s1, HMAC_DRBG_DATA_OFFSET
        mv      a4, s2
        call    hmac_sha256

        /* ---- Round 4: V = HMAC(K, V) -------------------------------- */
        mv      a0, s2
        li      a1, HMAC_DRBG_KEY_LEN
        mv      a2, s3
        li      a3, HMAC_DRBG_V_LEN
        mv      a4, s3
        call    hmac_sha256

.Lupdate_done:
        lw      s0, DRBG_S0_OFF(sp)
        lw      s1, DRBG_S1_OFF(sp)
        lw      s2, DRBG_S2_OFF(sp)
        lw      s3, DRBG_S3_OFF(sp)
        lw      s4, DRBG_S4_OFF(sp)
        lw      ra, DRBG_RA_OFF(sp)
        addi    sp, sp, DRBG_FRAME
        ret

/* ---- internal helpers (local labels — not callable) -----------------
 * These avoid duplicating the byte-copy loop body four times in the
 * caller. They use ra from the parent and clobber t0..t2 only. */

.Lcopy_v_to_buf:
        /* Copy 32 bytes from a1 (src) to a0 (dst) — used for the V
         * snapshot. 8-word unrolled for speed. */
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, \i(a1)
        sw      t0, \i(a0)
        .endr
        ret

.Lcopy_data:
        /* Copy a2 bytes from a1 (src) to a0 (dst) — byte-wise; a2 may
         * be any size up to HMAC_DRBG_SEED_LEN. */
        beqz    a2, 2f
1:      lbu     t0, 0(a1)
        sb      t0, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 1b
2:      ret

        .size   hmac_drbg_update, . - hmac_drbg_update
