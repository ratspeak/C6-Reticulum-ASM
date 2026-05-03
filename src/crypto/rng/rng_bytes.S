# ============================================================================
# @function:    rng_bytes
# @module:      crypto/rng
# @inputs:      a0 = out ptr (caller-owned, len bytes)
#               a1 = len     (number of bytes to emit; may be 0)
# @outputs:     out[0..len-1] filled with rng_counter-driven bytes:
#                 block_i = sha256(DETERMINISTIC_FAKE_RNG || counter_le32)
#                 counter ← counter + 1 after each emitted block.
#               When len % 32 != 0, the last block is truncated to the
#               remaining byte count.
# @clobbers:    t0..t6, a0..a7, ra, s0..s4
# @preserves:   sp, gp, all other callee-saved
# @stack:       176
# @cycles:      bounded (≈ ceil(len / 32) × sha256_compress)
# @ct:          required
# @spec:        DETERMINISTIC fake CSPRNG for QEMU bring-up. Replaced by
#               an HMAC-DRBG (NIST SP 800-90A) seeded from the on-chip
#               TRNG in production. The fake output is reproducible from
#               the seed string and the counter, which makes it
#               adequate for KAT-style testing of higher-level crypto
#               (notably x25519_keypair) without committing to a full
#               DRBG implementation in this milestone.
# @verify:      kat-only; deterministic fake CSPRNG. The QEMU pytest
#               compares the emitted bytes against a Python sha256-of-
#               (seed || counter_le32) oracle for several lengths
#               covering full and partial blocks. Once the production
#               HMAC-DRBG (NIST SP 800-90A) replaces this back-end we
#               will add a Cryptol/SAW algebraic equivalence proof
#               against the SHA-256 model already landed.
# @tests:       tests/crypto/rng/test_rng_bytes.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (144 bytes, 16-byte aligned):
 *   sp +   0 .. sp + 111: sha256_ctx (caller-owned scratch)
 *   sp + 112 .. sp + 115: counter_le32 (4 bytes; passed to sha256_update)
 *   sp + 116 .. sp + 119: digest scratch... no, use 32-byte digest_buf
 *   We need a 32-byte digest buffer for partial-block writes when the
 *   remaining length < 32. Move the layout to:
 *     sp + 0..111   sha256 ctx
 *     sp + 112..143 digest_buf (32 bytes)  ← also covers 16-byte align needs
 *     sp + 144..147 counter_le32          ← 4 more bytes
 *     sp + 148..151 saved ra              ← 4 bytes
 *     sp + 152..167 saved s0..s3          ← 16 bytes
 *     sp + 168..175 pad
 *     total 176 bytes (16-aligned).
 *
 * (We adjust the @stack header above to 176 to match — see the .equ
 * FRAME below.)
 */

        .include "rng.S"
        .include "sha256.S"

        .equ CTX_OFF,    0
        .equ DIGEST_OFF, 112
        .equ COUNTER_OFF,144
        .equ RA_OFF,     148
        .equ S0_OFF,     152
        .equ S1_OFF,     156
        .equ S2_OFF,     160
        .equ S3_OFF,     164
        .equ FRAME,      176

        .section .text.rng_bytes, "ax", @progbits
        .global rng_bytes
        .type   rng_bytes, @function
rng_bytes:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)

        beqz    a1, .Lrng_done                  /* nothing to do          */

        mv      s0, a0                          /* current out ptr        */
        mv      s1, a1                          /* remaining bytes        */
        la      s2, rng_counter                 /* &counter               */
        la      s3, DETERMINISTIC_FAKE_RNG      /* &seed                  */

.Lrng_block:
        /* Snapshot counter to a stack slot for sha256_update. */
        lw      t0, 0(s2)
        sw      t0, COUNTER_OFF(sp)

        /* sha256(seed || counter) → digest_buf */
        addi    a0, sp, CTX_OFF
        call    sha256_init

        addi    a0, sp, CTX_OFF
        mv      a1, s3
        li      a2, DETERMINISTIC_FAKE_RNG_LEN
        call    sha256_update

        addi    a0, sp, CTX_OFF
        addi    a1, sp, COUNTER_OFF
        li      a2, 4
        call    sha256_update

        addi    a0, sp, CTX_OFF
        addi    a1, sp, DIGEST_OFF
        call    sha256_final

        /* counter += 1 */
        lw      t0, 0(s2)
        addi    t0, t0, 1
        sw      t0, 0(s2)

        /* Copy min(remaining, 32) bytes from digest_buf to out */
        li      t1, RNG_OUTPUT_BLOCK            /* 32                     */
        bltu    s1, t1, .Lrng_partial

        /* Full 32-byte block */
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, (\i + DIGEST_OFF)(sp)
        sw      t0, \i(s0)
        .endr
        addi    s0, s0, 32
        addi    s1, s1, -32
        bnez    s1, .Lrng_block
        j       .Lrng_done

.Lrng_partial:
        /* Byte-by-byte copy of s1 (< 32) bytes from digest_buf to out */
        addi    t2, sp, DIGEST_OFF              /* src                    */
.Lrng_partial_loop:
        lbu     t0, 0(t2)
        sb      t0, 0(s0)
        addi    t2, t2, 1
        addi    s0, s0, 1
        addi    s1, s1, -1
        bnez    s1, .Lrng_partial_loop

.Lrng_done:
        lw      s3, S3_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   rng_bytes, . - rng_bytes
