/* RNG include — constants for the two-layer RNG (entropy source +
 * HMAC-DRBG-SHA-256 per NIST SP 800-90A Rev. 1 §10.1.2).
 *
 * The DETERMINISTIC_FAKE_RNG entropy seed in src/state/rng.S is
 * intentionally bright in the qemu-virt disassembly so a CI gate can
 * refuse a release build that would link the deterministic-fake into
 * a production image. See docs/milestones/milestone-2.md §rng.
 */

        .equ RNG_OUTPUT_BLOCK,           32     /* SHA-256 digest size  */
        .equ DETERMINISTIC_FAKE_RNG_LEN, 32     /* matches src/state/rng.S */

        /* ---- HMAC-DRBG-SHA-256 (NIST SP 800-90A Rev. 1 §10.1.2) ----
         *
         * Security strength: 256 bits. Min entropy_input = 32 bytes
         * (security_strength). Min nonce = 16 bytes (security_strength/2).
         * seed_material = entropy_input || nonce || personalization;
         * personalization is null in our build, so seed_len = 48 bytes.
         *
         * Reseed interval is a configuration parameter, not a hard
         * NIST limit; we expose `rng_init` as the explicit reseed
         * entry point and do not auto-reseed inside `rng_bytes` (the
         * counter is opaque to callers — it serves as the "init flag"
         * + a debugger-visible generation counter). Callers can
         * re-invoke `rng_init` at any time to reseed.
         */
        .equ HMAC_DRBG_KEY_LEN,          32     /* HMAC-SHA-256 output  */
        .equ HMAC_DRBG_V_LEN,            32     /* DRBG state V         */
        .equ HMAC_DRBG_SEED_LEN,         48     /* entropy_input(32) + nonce(16) */
        .equ HMAC_DRBG_BUF_LEN,          96     /* V(32) + sep(1) + data(48) → 81, padded */
        .equ HMAC_DRBG_SEP_OFFSET,       32     /* sep byte position in buf */
        .equ HMAC_DRBG_DATA_OFFSET,      33     /* data start position in buf */
