/* RNG state — DETERMINISTIC FAKE for QEMU bring-up. The production
 * ESP32-C6 driver replaces this with the on-chip TRNG (per ADR / TRM
 * Ch 38). The symbol DETERMINISTIC_FAKE_RNG is intentionally bright in
 * the disassembly so a release build cannot ship with this in place
 * (a CI gate will refuse). See docs/milestones/milestone-2.md §rng.
 */

        .equ RNG_OUTPUT_BLOCK,           32     /* SHA-256 digest size  */
        .equ DETERMINISTIC_FAKE_RNG_LEN, 32     /* matches src/state/rng.S */
