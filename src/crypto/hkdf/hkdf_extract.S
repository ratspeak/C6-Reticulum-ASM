# ============================================================================
# @function:    hkdf_extract
# @module:      crypto/hkdf
# @inputs:      a0 = salt_ptr (may be null when salt_len == 0), a1 = salt_len, a2 = ikm_ptr, a3 = ikm_len, a4 = prk_out (32 bytes)
# @outputs:     32-byte PRK = HMAC-SHA-256(salt or zeros, IKM) at prk_out
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, callee-saved
# @stack:       16
# @cycles:      bounded (one HMAC-SHA-256 over ikm_len bytes)
# @ct:          required
# @spec:        RFC 5869 §2.2 (Extract)
# @verify:      kat-only; integration via the 'E' marker in _main, validated against RFC 5869 Appendix A vectors in tests/crypto/hkdf/test_hkdf_kat.py
# @tests:       tests/crypto/hkdf/test_hkdf_extract.py
# @adrs:        0001, 0002, 0006
# @status:      tested
# ============================================================================

/* HKDF-Extract per RFC 5869 §2.2:
 *
 *     PRK = HMAC-SHA-256(salt, IKM)
 *
 * If salt_len == 0 the spec treats salt as 32 zero bytes; we provide
 * those via the .rodata `hkdf_zero_salt` symbol so callers can pass
 * any pointer (or NULL — we never dereference it).
 */

        .include "hkdf.S"

        .section .text.hkdf_extract, "ax", @progbits
        .global hkdf_extract
        .type   hkdf_extract, @function
hkdf_extract:
        addi    sp, sp, -16
        sw      ra, 12(sp)

        /* Substitute the zero salt when caller gave us an empty one. */
        bnez    a1, 1f
        la      a0, hkdf_zero_salt
        li      a1, HKDF_HASH_LEN
1:
        /* HMAC-SHA-256(salt, IKM) → prk_out
         * a0=salt, a1=salt_len, a2=ikm, a3=ikm_len, a4=prk_out. */
        call    hmac_sha256

        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   hkdf_extract, . - hkdf_extract
