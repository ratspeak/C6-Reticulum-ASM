/* ============================================================================
 * RNG statically allocated state — DETERMINISTIC FAKE for QEMU bring-up.
 *
 * Production ESP32-C6 builds replace this back-end with the on-chip TRNG
 * (per docs/milestones/milestone-2.md §rng). The DETERMINISTIC_FAKE_RNG
 * marker symbol must NOT survive into a release artifact — CI gates on
 * its presence in the linked ELF for `target=esp32c6`.
 *
 * No instructions live here.
 * ============================================================================
 */

        .include "rng.S"

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
