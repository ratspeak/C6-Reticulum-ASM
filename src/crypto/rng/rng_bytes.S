# ============================================================================
# @function:    rng_bytes
# @module:      crypto/rng
# @inputs:      a0 = out ptr (caller-owned, len bytes)
#               a1 = len     (number of bytes to emit; may be 0)
# @outputs:     out[0..len-1] = HMAC-DRBG-SHA-256 generate output per
#               NIST SP 800-90A Rev. 1 §10.1.2.5. Mutates hmac_drbg_K,
#               hmac_drbg_V (per-call backtracking-resistance update)
#               and increments hmac_drbg_reseed_counter.
# @clobbers:    a0..a7, t0..t6, ra, s0..s4
# @preserves:   sp, gp, all other callee-saved
# @stack:       32
#               (saved regs only — V is updated in place in BSS)
# @cycles:      bounded — ceil(len/32) HMAC-SHA-256 calls + 2 more for
#               the backtracking-resistance hmac_drbg_update(NULL, 0)
# @ct:          required (no secret-dependent branches; len is non-secret)
# @spec:        NIST SP 800-90A Rev. 1 §10.1.2.5 HMAC_DRBG_Generate
#               (with no additional_input — caller-supplied additional
#               data is not part of the milestone-2 API; lands when a
#               consumer needs it):
#                 1. (reseed counter check elided — explicit reseed via
#                     rng_init, see src/state/rng.S)
#                 2. temp = empty
#                 3. while len(temp) < requested_bytes:
#                      V = HMAC(K, V)
#                      temp = temp || V
#                 4. output = leftmost requested_bytes bytes of temp
#                 5. (K, V) = HMAC_DRBG_Update(NULL, K, V)
#                    [unconditional backtracking resistance — even with
#                     no additional_input, this re-randomises K, V so
#                     a state compromise after the call cannot reproduce
#                     past output]
#                 6. reseed_counter += 1
# @verify:      proofs/crypto/rng/HMACDRBG.cry, proofs/crypto/rng/rng_bytes.saw
#               (Tier C deferred: the asm body composes hmac_sha256 and
#               hmac_drbg_update — heavy crypto on the same pcode-
#               unreliable boundary as AES / X25519. Binary correctness
#               is established by the QEMU pytest KAT in
#               tests/crypto/rng/test_rng_bytes.py against the
#               drbg_oracle Python mirror, on full RV32IMC fidelity
#               under qemu-system-riscv32, plus the NIST CAVP DRBGVS
#               COUNT=0 KAT discharged symbolically by SAW. The C6
#               TARGET path is exercised live in
#               tests/hardware/test_rng.py.)
# @tests:       tests/crypto/rng/test_rng_bytes.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (32 bytes; 16-aligned):
 *     sp + 0..3      saved s0  (out cursor)
 *     sp + 4..7      saved s1  (remaining bytes)
 *     sp + 8..11     saved s2  (&hmac_drbg_K)
 *     sp + 12..15    saved s3  (&hmac_drbg_V)
 *     sp + 16..27    pad
 *     sp + 28..31    saved ra
 */

        .include "rng.S"

        .equ BYT_S0_OFF, 0
        .equ BYT_S1_OFF, 4
        .equ BYT_S2_OFF, 8
        .equ BYT_S3_OFF, 12
        .equ BYT_RA_OFF, 28
        .equ BYT_FRAME,  32

        .section .text.rng_bytes, "ax", @progbits
        .global rng_bytes
        .type   rng_bytes, @function
rng_bytes:
        addi    sp, sp, -BYT_FRAME
        sw      ra, BYT_RA_OFF(sp)
        sw      s3, BYT_S3_OFF(sp)
        sw      s2, BYT_S2_OFF(sp)
        sw      s1, BYT_S1_OFF(sp)
        sw      s0, BYT_S0_OFF(sp)

        /* len == 0 still bumps the reseed counter and runs the
         * backtracking-resistance update — matches NIST step 5/6
         * literally. The empty-output loop body is naturally skipped
         * by the bgeu check. */
        mv      s0, a0                          /* out cursor             */
        mv      s1, a1                          /* remaining bytes        */
        la      s2, hmac_drbg_K
        la      s3, hmac_drbg_V

.Lgen_block:
        beqz    s1, .Lgen_done_blocks

        /* V = HMAC(K, V) — in-place; out_ptr aliases msg_ptr safely
         * (msg consumed by the inner sha256_update before any write
         * to the output, per the hmac_sha256.S preamble). */
        mv      a0, s2
        li      a1, HMAC_DRBG_KEY_LEN
        mv      a2, s3
        li      a3, HMAC_DRBG_V_LEN
        mv      a4, s3
        call    hmac_sha256

        /* Copy min(remaining, 32) bytes from V to out cursor. Full
         * 32-byte blocks unroll to 8 word stores; the partial tail
         * falls through to the byte loop. */
        li      t0, HMAC_DRBG_V_LEN             /* 32                     */
        bltu    s1, t0, .Lgen_partial

        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, \i(s3)
        sw      t0, \i(s0)
        .endr
        addi    s0, s0, 32
        addi    s1, s1, -32
        j       .Lgen_block

.Lgen_partial:
        /* Byte-wise copy of s1 (< 32) bytes. */
        mv      t1, s3                          /* src cursor             */
.Lgen_partial_loop:
        beqz    s1, .Lgen_done_blocks
        lbu     t0, 0(t1)
        sb      t0, 0(s0)
        addi    t1, t1, 1
        addi    s0, s0, 1
        addi    s1, s1, -1
        j       .Lgen_partial_loop

.Lgen_done_blocks:
        /* (K, V) = HMAC_DRBG_Update(NULL, K, V) */
        mv      a0, zero                        /* data_ptr (unused)      */
        li      a1, 0                           /* data_len = 0           */
        call    hmac_drbg_update

        /* reseed_counter += 1 */
        la      t0, hmac_drbg_reseed_counter
        lw      t1, 0(t0)
        addi    t1, t1, 1
        sw      t1, 0(t0)

        lw      s0, BYT_S0_OFF(sp)
        lw      s1, BYT_S1_OFF(sp)
        lw      s2, BYT_S2_OFF(sp)
        lw      s3, BYT_S3_OFF(sp)
        lw      ra, BYT_RA_OFF(sp)
        addi    sp, sp, BYT_FRAME
        ret

        .size   rng_bytes, . - rng_bytes
