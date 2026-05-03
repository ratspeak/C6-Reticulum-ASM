/* ============================================================================
 * RNG statically allocated state — two layers.
 *
 *   1. Raw entropy source (consumed by `rng_entropy`):
 *      * TARGET_QEMU_VIRT: deterministic-fake CSPRNG —
 *        sha256(DETERMINISTIC_FAKE_RNG || rng_counter_le32),
 *        counter incremented per 32-byte block. Reproducible from the
 *        seed string for KAT-style testing of higher-level crypto.
 *      * TARGET_C6:        ESP32-C6 LPPERI on-chip hardware RNG
 *        (no statically-allocated state on this path; the chip's
 *        analog noise source is the entropy pool).
 *      The DETERMINISTIC_FAKE_RNG marker symbol is intentionally bright
 *      in the qemu-virt disassembly so a CI gate can refuse a release
 *      build that would link the deterministic-fake into a production
 *      image.
 *
 *   2. HMAC-DRBG-SHA-256 (consumed by `rng_init` and `rng_bytes`):
 *      NIST SP 800-90A Rev. 1 §10.1.2. The DRBG is instantiated by
 *      `rng_init` from `rng_entropy(48)` (32-byte entropy_input +
 *      16-byte nonce; null personalization string), and `rng_bytes`
 *      is the generate operation with unconditional per-call backtrack
 *      resistance. The reseed counter is opaque to callers and is the
 *      "init flag": 0 = uninitialized; ≥1 = generation count since
 *      instantiate (sticky non-zero — `rng_init` may be re-invoked at
 *      any time to reseed).
 *
 * No instructions live here. See docs/milestones/milestone-2.md §rng.
 * ============================================================================
 */

        .include "rng.S"

        /* ---- Layer 1: entropy source ----------------------------------- */
        .section .rodata.rng_seed, "a"
        .global DETERMINISTIC_FAKE_RNG
        .type   DETERMINISTIC_FAKE_RNG, @object
        .balign 4
DETERMINISTIC_FAKE_RNG:
        .ascii "DETERMINISTIC_FAKE_RNG_FOR_QEMU"
        # 31 ascii bytes; one trailing zero pads to DETERMINISTIC_FAKE_RNG_LEN.
        .byte  0x00
        .size  DETERMINISTIC_FAKE_RNG, . - DETERMINISTIC_FAKE_RNG

        .section .bss.rng_counter, "aw", @nobits
        .global rng_counter
        .type   rng_counter, @object
        .balign 4
rng_counter:
        .zero   4
        .size   rng_counter, 4

        /* ---- Layer 2: HMAC-DRBG-SHA-256 state -------------------------- */
        .section .bss.hmac_drbg, "aw", @nobits
        .global hmac_drbg_K
        .type   hmac_drbg_K, @object
        .balign 4
hmac_drbg_K:
        .zero   HMAC_DRBG_KEY_LEN              /* 32 */
        .size   hmac_drbg_K, HMAC_DRBG_KEY_LEN

        .global hmac_drbg_V
        .type   hmac_drbg_V, @object
        .balign 4
hmac_drbg_V:
        .zero   HMAC_DRBG_V_LEN                /* 32 */
        .size   hmac_drbg_V, HMAC_DRBG_V_LEN

        .global hmac_drbg_reseed_counter
        .type   hmac_drbg_reseed_counter, @object
        .balign 4
hmac_drbg_reseed_counter:
        .zero   4                              /* 0 = uninitialized */
        .size   hmac_drbg_reseed_counter, 4

        /* Scratch for the HMAC-DRBG_Update input layout
         *   V[32] || sep[1] || provided_data[0..HMAC_DRBG_SEED_LEN]
         * Sized at HMAC_DRBG_BUF_LEN bytes (32 + 1 + 48 = 81, padded
         * to 96 for 4-byte alignment headroom). The 48-byte data cap
         * matches HMAC_DRBG_SEED_LEN; no other call site exceeds that. */
        .global hmac_drbg_buf
        .type   hmac_drbg_buf, @object
        .balign 4
hmac_drbg_buf:
        .zero   HMAC_DRBG_BUF_LEN              /* 96 */
        .size   hmac_drbg_buf, HMAC_DRBG_BUF_LEN
