# ============================================================================
# @function:    log_init
# @module:      log
# @inputs:      (none)
# @outputs:     (log subsystem ready; ts source initialised when implemented)
# @clobbers:    (none today)
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~1 today; ~tens once mtime baseline is captured)
# @ct:          not-required
# @spec:        ADR-0004 §API; milestone-1 §log
# @verify:      kat-only; bring-up only, real ts source lands with clock_get_freq
# @tests:       tests/log/test_log_init.py
# @adrs:        0004
# @status:      verified
# ============================================================================

/* Today this is `ret` — log_event currently emits a fixed `00000000`
 * timestamp (per ADR-0008 the format is 8 hex digits). When clock_get_freq
 * lands, log_init will sample the timer baseline so log_event can emit a
 * real ms-since-boot value. The function exists now so the ADR-0004 API
 * is callable from _main without a forward dependency.
 */

        .section .text.log_init, "ax", @progbits
        .global log_init
        .type   log_init, @function
log_init:
        ret
        .size   log_init, . - log_init
