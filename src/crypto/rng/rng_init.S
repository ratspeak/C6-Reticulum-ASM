# ============================================================================
# @function:    rng_init
# @module:      crypto/rng
# @inputs:      (none)
# @outputs:     hmac_drbg_K, hmac_drbg_V, hmac_drbg_reseed_counter all set
#               per NIST SP 800-90A Rev. 1 §10.1.2.3 HMAC_DRBG_Instantiate.
#               Also resets the qemu deterministic-fake CSPRNG counter
#               (rng_counter) so KAT tests get reproducible output across
#               boot cycles.
# @clobbers:    a0..a7, t0..t6, ra, s0..s4
# @preserves:   sp, gp, all other callee-saved
# @stack:       80
#               (48-byte seed scratch + saved regs)
# @cycles:      bounded — one rng_entropy(48) call + one hmac_drbg_update(48)
# @ct:          required — no secret-dependent branches; rng_entropy and
#               hmac_drbg_update are themselves @ct=required
# @spec:        NIST SP 800-90A Rev. 1 §10.1.2.3 HMAC_DRBG_Instantiate:
#                 1. seed_material = entropy_input || nonce || personalization
#                 2. K = 0x00 * outlen
#                 3. V = 0x01 * outlen
#                 4. (K, V) = HMAC_DRBG_Update(seed_material, K, V)
#                 5. reseed_counter = 1
#               outlen = 256 bits (HMAC-SHA-256 output).
#               security_strength = 256 bits → entropy_input ≥ 32 bytes,
#               nonce ≥ 16 bytes. Personalization is null in this build.
#               seed_material is therefore 48 bytes from rng_entropy.
# @verify:      proofs/crypto/rng/HMACDRBG.cry, proofs/crypto/rng/rng_init.saw
#               (Tier C deferred: the asm body composes rng_entropy and
#               hmac_drbg_update which run sha256_compress / hmac_sha256
#               heavy crypto loops; angr's pcode RV32IMC engine
#               miscompiles these by the same mechanism documented for
#               the AES Boyar-Peralta circuit and X25519 64-bit
#               accumulator chain — see ADR-0009 §"Tier C path forward".
#               Binary correctness is established by the QEMU pytest
#               KAT in tests/crypto/rng/test_rng_init.py against the
#               drbg_oracle Python mirror, run on full RV32IMC fidelity
#               under qemu-system-riscv32.)
# @tests:       tests/crypto/rng/test_rng_init.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (80 bytes; 16-aligned):
 *     sp + 0..47      seed_material scratch (entropy_input + nonce)
 *     sp + 48..51     saved s0
 *     sp + 52..55     saved ra
 *     sp + 56..79     pad
 */

        .include "rng.S"

        .equ INIT_SEED_OFF, 0
        .equ INIT_S0_OFF,   48
        .equ INIT_RA_OFF,   52
        .equ INIT_FRAME,    80

        .section .text.rng_init, "ax", @progbits
        .global rng_init
        .type   rng_init, @function
rng_init:
        addi    sp, sp, -INIT_FRAME
        sw      ra, INIT_RA_OFF(sp)
        sw      s0, INIT_S0_OFF(sp)

        /* 1. Reset the qemu deterministic-fake counter so a re-init
         *    from the same boot gets the same seed_material. On
         *    TARGET_C6 rng_counter is unused (rng_entropy reads
         *    LPPERI directly); the store is harmless. */
        la      t0, rng_counter
        sw      zero, 0(t0)

        /* 2. Gather 48 bytes of seed_material via the raw entropy
         *    source. Stack-resident — never observable to non-DRBG
         *    callers. */
        mv      a0, sp                          /* &seed_material        */
        li      a1, HMAC_DRBG_SEED_LEN
        call    rng_entropy

        /* 3. K = 0x00 * 32  (already zeroed by _init_bss but rewrite
         *    explicitly so a re-instantiate from a non-virgin state is
         *    well-defined). */
        la      t0, hmac_drbg_K
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        sw      zero, \i(t0)
        .endr

        /* 4. V = 0x01 * 32 */
        la      t0, hmac_drbg_V
        li      t1, 0x01010101
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        sw      t1, \i(t0)
        .endr

        /* 5. (K, V) = HMAC_DRBG_Update(seed_material, K, V) */
        mv      a0, sp                          /* &seed_material        */
        li      a1, HMAC_DRBG_SEED_LEN
        call    hmac_drbg_update

        /* 6. reseed_counter = 1 */
        la      t0, hmac_drbg_reseed_counter
        li      t1, 1
        sw      t1, 0(t0)

        lw      s0, INIT_S0_OFF(sp)
        lw      ra, INIT_RA_OFF(sp)
        addi    sp, sp, INIT_FRAME
        ret

        .size   rng_init, . - rng_init
