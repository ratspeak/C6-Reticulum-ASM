# ============================================================================
# @function:    rng_entropy
# @module:      crypto/rng
# @inputs:      a0 = out ptr (caller-owned, len bytes)
#               a1 = len     (number of bytes to emit; may be 0)
# @outputs:     TARGET_QEMU_VIRT:
#                 out[0..len-1] = sha256(DETERMINISTIC_FAKE_RNG || counter_le32)
#                 with counter incremented per 32-byte block. Output is
#                 fully reproducible from the seed string + counter — the
#                 deterministic-fake CSPRNG documented below.
#               TARGET_C6:
#                 out[0..len-1] streamed from the LPPERI on-chip RNG (one
#                 32-bit read every ~64 CPU cycles per the esp-idf
#                 hw_random.c inter-read guidance).
# @clobbers:    t0..t6, a0..a7, ra, s0..s4
# @preserves:   sp, gp, all other callee-saved
# @stack:       176
#               (TARGET_QEMU_VIRT path; the TARGET_C6 path is
#               a leaf with @stack = 0, but the static analyzer
#               uses worst-case which is the qemu sha256 frame.)
# @cycles:      bounded (TARGET_QEMU_VIRT: ≈ ceil(len/32) × sha256_compress;
#               TARGET_C6: ≈ len × 80 — one 32-bit RNG read + ~64-cycle
#               settle-delay every 4 bytes)
# @ct:          required
# @spec:        Internal entropy source for the two-layer RNG. The
#               TARGET_QEMU_VIRT path is a deterministic CSPRNG (so KAT
#               tests can pin DRBG output transitively); the TARGET_C6
#               path reads the ESP32-C6 TRM Ch 38 LPPERI on-chip RNG via
#               LPPERI_RNG_DATA at 0x600B2808. esp-idf hw_random.c is the
#               reference for the inter-read settle delay. This function
#               feeds `rng_init`'s HMAC-DRBG instantiate; callers wanting
#               cryptographic-grade output use `rng_bytes` instead.
# @verify:      kat-only on the qemu-virt path: tests/crypto/rng/test_rng_entropy.py
#               compares emitted bytes against a Python sha256(seed ||
#               counter_le32) oracle. TARGET_C6 path is exercised by the
#               DRBG instantiate (which feeds 48 bytes through the DRBG
#               update path covered by HMAC Tier A).
# @tests:       tests/crypto/rng/test_rng_entropy.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame layout (qemu path; identical to the prior rng_bytes layout
 * since this is verbatim a rename of that body):
 *     sp + 0..111    sha256 ctx
 *     sp + 112..143  digest_buf (32 bytes)
 *     sp + 144..147  counter_le32
 *     sp + 148..151  saved ra
 *     sp + 152..167  saved s0..s3
 *     sp + 168..175  pad
 *     total 176 bytes (16-aligned).
 */

        .include "regs.S"
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

        .section .text.rng_entropy, "ax", @progbits
        .global rng_entropy
        .type   rng_entropy, @function
rng_entropy:
        .ifdef TARGET_C6
        /* Hardware RNG path — leaf, no spill. Read LPPERI_RNG_DATA in
         * 32-bit chunks, emit 4 bytes per read, then settle for ~64 CPU
         * cycles before the next read (esp-idf's hw_random.c uses ~16
         * APB cycles between reads to avoid draining entropy faster than
         * the analog noise source can replenish; 64 CPU cycles is a 4×
         * margin at 80 MHz CPU / 20 MHz APB). */
        beqz    a1, .Lhw_done
        li      t0, LPPERI_RNG_DATA
        mv      t1, a0                  /* out cursor                     */
        mv      t2, a1                  /* remaining bytes                */
.Lhw_word:
        lw      t3, 0(t0)               /* 4 bytes of entropy             */
        li      t4, 4                   /* bytes left in this word        */
.Lhw_byte:
        beqz    t2, .Lhw_done
        beqz    t4, .Lhw_settle
        sb      t3, 0(t1)
        srli    t3, t3, 8
        addi    t1, t1, 1
        addi    t2, t2, -1
        addi    t4, t4, -1
        j       .Lhw_byte
.Lhw_settle:
        /* ~64-cycle delay before next RNG read. The loop body is 2
         * instructions; 32 iterations gives ~64 cycles plus 1 cycle of
         * branch mispredict per iteration on simple in-order cores
         * (≈ 96 wall cycles in practice — within margin). */
        li      t4, 32
.Lhw_settle_loop:
        addi    t4, t4, -1
        bnez    t4, .Lhw_settle_loop
        j       .Lhw_word
.Lhw_done:
        ret
        .endif

        .ifdef TARGET_QEMU_VIRT
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)

        beqz    a1, .Lent_done                  /* nothing to do          */

        mv      s0, a0                          /* current out ptr        */
        mv      s1, a1                          /* remaining bytes        */
        la      s2, rng_counter                 /* &counter               */
        la      s3, DETERMINISTIC_FAKE_RNG      /* &seed                  */

.Lent_block:
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
        bltu    s1, t1, .Lent_partial

        /* Full 32-byte block */
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, (\i + DIGEST_OFF)(sp)
        sw      t0, \i(s0)
        .endr
        addi    s0, s0, 32
        addi    s1, s1, -32
        bnez    s1, .Lent_block
        j       .Lent_done

.Lent_partial:
        /* Byte-by-byte copy of s1 (< 32) bytes from digest_buf to out */
        addi    t2, sp, DIGEST_OFF              /* src                    */
.Lent_partial_loop:
        lbu     t0, 0(t2)
        sb      t0, 0(s0)
        addi    t2, t2, 1
        addi    s0, s0, 1
        addi    s1, s1, -1
        bnez    s1, .Lent_partial_loop

.Lent_done:
        lw      s3, S3_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret
        .endif

        .size   rng_entropy, . - rng_entropy
