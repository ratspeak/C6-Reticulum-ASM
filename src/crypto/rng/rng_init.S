# ============================================================================
# @function:    rng_init
# @module:      crypto/rng
# @inputs:      (none)
# @outputs:     rng_counter = 0; subsequent rng_bytes() output is
#               sha256(DETERMINISTIC_FAKE_RNG || counter_le_32) for
#               counter = 0, 1, 2, ...
# @clobbers:    t0
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~3)
# @ct:          required
# @spec:        DETERMINISTIC fake-entropy initialiser for the QEMU
#               bring-up build. The production ESP32-C6 build will
#               replace this with the on-chip TRNG enable + warm-up
#               sequence per the C6 TRM. The fake source is documented
#               and CI-gated in src/state/rng.S.
# @verify:      kat-only; deterministic fake-RNG initialiser. No
#               algebraic content beyond `rng_counter := 0`; the QEMU
#               smoke test asserts the post-condition transitively by
#               checking that the first emitted block equals
#               sha256(SEED || u32_le(0)). Real entropy enable for the
#               ESP32-C6 TRNG arrives in the production rng_init replacement.
# @tests:       tests/crypto/rng/test_rng_init.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

        .include "rng.S"

        .section .text.rng_init, "ax", @progbits
        .global rng_init
        .type   rng_init, @function
rng_init:
        la      t0, rng_counter
        sw      zero, 0(t0)
        ret

        .size   rng_init, . - rng_init
