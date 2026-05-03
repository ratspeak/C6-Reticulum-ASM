# ============================================================================
# @function:    ed25519_sign
# @module:      crypto/ed25519
# @inputs:      a0 = sig_out ptr (64 bytes; R || s)
#               a1 = msg_ptr
#               a2 = msg_len   (bytes; ≤ 2^32 − 1)
#               a3 = sk_ptr    (32 bytes; the seed)
# @outputs:     sig_out = R_bytes (32) || s_bytes (32) per RFC 8032 §5.1.6.
# @clobbers:    t0..t6, a4..a7, s0..s4
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       384
# @cycles:      bounded (≈ 3 sha512 + 2 scalarmult + 2 sc_reduce + 1
#               sc_muladd + 1 compress ≈ 20M)
# @ct:          required (each sub-primitive is CT; sk and prefix are
#               secret; r is derived deterministically and stays
#               internal until R is published).
# @spec:        RFC 8032 §5.1.6 — Ed25519 deterministic signing.
#                 1. h := SHA-512(seed)         (64 bytes)
#                 2. a := clamp(h[0..31])       (secret scalar)
#                 3. prefix := h[32..63]
#                 4. pk := compress(a · B)
#                 5. r := SHA-512(prefix || M)  → reduce mod L
#                 6. R := compress(r · B)
#                 7. k := SHA-512(R || pk || M) → reduce mod L
#                 8. s := (k * a + r) mod L
#                 9. sig := R || s_LE
# @verify:      kat-only; ed25519_sign is end-to-end glue over
#               sha512_* + ed25519_scalarmult + ed25519_point_compress
#               + ed25519_sc_reduce + ed25519_sc_muladd. Each
#               underlying primitive now carries Tier A Cryptol+SAW
#               (proofs/crypto/sha512/, proofs/crypto/ed25519/) plus
#               per-function Tier C QEMU/pyca KATs; the sign-level
#               QEMU pytest verifies the produced signature against
#               pyca/cryptography's Ed25519PrivateKey.sign on a
#               battery of (seed, message) pairs including RFC 8032
#               §7.1. A dedicated sign-level Tier A would have to
#               symbolically run two SHA-512 invocations + scalarmult
#               + compress + sc_reduce + sc_muladd, which is dominated
#               by the underlying tier-A coverage.
# @tests:       tests/crypto/ed25519/test_ed25519_sign.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (384 bytes, 16-byte aligned):
 *      0..63    h_buf       (SHA-512 output from seed; a = clamped lo32)
 *     64..95    pk_bytes    (encoded pk; needed for step 7 SHA-512 input)
 *     96..127   R_bytes     (encoded R; goes into sig_out and step 7)
 *    128..159   r_buf       (32-byte scalar after reduce)
 *    160..191   k_buf       (32-byte scalar after reduce)
 *    192..351   point_buf   (160-byte point; reused for pk and R)
 *    352..355   s4
 *    356..359   s3
 *    360..363   s2
 *    364..367   s1
 *    368..371   s0
 *    372..375   ra
 *    376..383   pad
 *
 * Saved regs:
 *   s0 = sig_out ptr
 *   s1 = msg_ptr
 *   s2 = msg_len
 *   s3 = sk_ptr
 *   s4 = scratch
 */

        .include "ed25519.S"
        .include "sha512.S"

        .equ H_OFF,       0
        .equ PK_OFF,     64
        .equ R_OFF,      96
        .equ R_SC_OFF,  128       /* r as scalar (32 LE bytes)            */
        .equ K_SC_OFF,  160       /* k as scalar (32 LE bytes)            */
        .equ POINT_OFF, 192
        .equ S4_OFF,    352
        .equ S3_OFF,    356
        .equ S2_OFF,    360
        .equ S1_OFF,    364
        .equ S0_OFF,    368
        .equ RA_OFF,    372
        .equ FRAME,     384

        .section .text.ed25519_sign, "ax", @progbits
        .global ed25519_sign
        .type   ed25519_sign, @function
ed25519_sign:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        mv      s0, a0                          /* sig_out                */
        mv      s1, a1                          /* msg_ptr                */
        mv      s2, a2                          /* msg_len                */
        mv      s3, a3                          /* sk_ptr                 */

        # ---- 1. h := SHA-512(seed) ----
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        mv      a1, s3
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        addi    a1, sp, H_OFF
        call    sha512_final

        # ---- 2. Clamp h[0..31] in place: a = (h[0]&248, h[1..30], (h[31]&127)|64) ----
        lbu     t0, H_OFF(sp)
        andi    t0, t0, 248
        sb      t0, H_OFF(sp)
        lbu     t0, (H_OFF + 31)(sp)
        andi    t0, t0, 127
        ori     t0, t0, 64
        sb      t0, (H_OFF + 31)(sp)

        # ---- 3. prefix is h[32..63] (left in place) ----

        # ---- 4. pk := compress(a · B) ----
        addi    a0, sp, POINT_OFF
        addi    a1, sp, H_OFF                   /* clamped scalar a       */
        la      a2, ed25519_base_point
        call    ed25519_scalarmult
        addi    a0, sp, PK_OFF
        addi    a1, sp, POINT_OFF
        call    ed25519_point_compress

        # ---- 5. r := reduce(SHA-512(prefix || msg)) ----
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        addi    a1, sp, (H_OFF + 32)            /* prefix                 */
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        mv      a1, s1                          /* message                */
        mv      a2, s2
        call    sha512_update
        la      a0, sha512_ctx
        la      a1, sha512_digest_buf
        call    sha512_final
        # reduce 64-byte digest into r (32 LE bytes)
        addi    a0, sp, R_SC_OFF
        la      a1, sha512_digest_buf
        call    ed25519_sc_reduce

        # ---- 6. R := compress(r · B) ----
        addi    a0, sp, POINT_OFF
        addi    a1, sp, R_SC_OFF
        la      a2, ed25519_base_point
        call    ed25519_scalarmult
        addi    a0, sp, R_OFF
        addi    a1, sp, POINT_OFF
        call    ed25519_point_compress

        # ---- 7. k := reduce(SHA-512(R || pk || msg)) ----
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        addi    a1, sp, R_OFF
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        addi    a1, sp, PK_OFF
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        mv      a1, s1
        mv      a2, s2
        call    sha512_update
        la      a0, sha512_ctx
        la      a1, sha512_digest_buf
        call    sha512_final
        addi    a0, sp, K_SC_OFF
        la      a1, sha512_digest_buf
        call    ed25519_sc_reduce

        # ---- 8. s := (k * a + r) mod L  via sc_muladd(k, a, r) ----
        # Note sc_muladd signature: (out, a, b, c) computes (a*b+c) mod L.
        # We want (k*a+r), so a_arg = k, b_arg = a (clamped scalar), c_arg = r.
        addi    a0, s0, 32                      /* sig_out + 32 = s slot  */
        addi    a1, sp, K_SC_OFF
        addi    a2, sp, H_OFF                   /* clamped a is here      */
        addi    a3, sp, R_SC_OFF
        call    ed25519_sc_muladd

        # ---- 9. sig_out[0..31] := R_bytes ----
        addi    t0, sp, R_OFF
        mv      t1, s0
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t2, \i(t0)
        sw      t2, \i(t1)
        .endr

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_sign, . - ed25519_sign
