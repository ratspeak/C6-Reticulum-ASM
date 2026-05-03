# ============================================================================
# @function:    sha512_init
# @module:      crypto/sha512
# @inputs:      a0 = ctx_ptr (sha512_ctx; 208 bytes, 8-byte aligned, caller-owned)
# @outputs:     ctx->H[0..7] populated with FIPS 180-4 §5.3.5 IVs;
#               ctx->length_bits = 0; ctx->block_len = 0
# @clobbers:    t0..t6
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~50: 16 BE 32-bit IV stores + 3 zero stores)
# @ct:          required
# @spec:        FIPS 180-4 §5.3.5 — SHA-512 initial hash values
#                 H_0..H_7 = first 64 bits of the fractional parts of the
#                 square roots of the first 8 primes (2..19). Stored as
#                 little-endian 32-bit half-words on RV32.
# @verify:      kat-only; entry-point glue that copies the FIPS 180-4
#               §5.3.5 IV table into ctx->H and zeroes length_bits +
#               block_len. Correctness is established transitively by
#               the SHA-512 family KAT (which only succeeds if init
#               sets the right starting state).
# @tests:       tests/crypto/sha512/test_sha512_kat.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

        .include "sha512.S"

        .section .rodata.sha512_init_iv, "a"
        .balign 4
sha512_init_iv:
        # H_0 = 0x6a09e667f3bcc908   stored as (lo, hi) little-endian pair
        .word 0xf3bcc908, 0x6a09e667
        # H_1 = 0xbb67ae8584caa73b
        .word 0x84caa73b, 0xbb67ae85
        # H_2 = 0x3c6ef372fe94f82b
        .word 0xfe94f82b, 0x3c6ef372
        # H_3 = 0xa54ff53a5f1d36f1
        .word 0x5f1d36f1, 0xa54ff53a
        # H_4 = 0x510e527fade682d1
        .word 0xade682d1, 0x510e527f
        # H_5 = 0x9b05688c2b3e6c1f
        .word 0x2b3e6c1f, 0x9b05688c
        # H_6 = 0x1f83d9abfb41bd6b
        .word 0xfb41bd6b, 0x1f83d9ab
        # H_7 = 0x5be0cd19137e2179
        .word 0x137e2179, 0x5be0cd19

        .section .text.sha512_init, "ax", @progbits
        .global sha512_init
        .type   sha512_init, @function
sha512_init:
        la      t0, sha512_init_iv
        # Copy 16 32-bit words (= 8 × 64-bit) into ctx->H.
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60
        lw      t1, \i(t0)
        sw      t1, (\i + SHA512_CTX_H)(a0)
        .endr
        # length_bits (64-bit, two zero words)
        sw      zero, SHA512_CTX_LEN_BITS(a0)
        sw      zero, (SHA512_CTX_LEN_BITS + 4)(a0)
        # block_len = 0
        sw      zero, SHA512_CTX_BLOCK_LEN(a0)
        ret

        .size   sha512_init, . - sha512_init
