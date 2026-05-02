# ============================================================================
# @function:    aes_addroundkey
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes, 4-byte aligned)
#               a1 = round_key ptr (16 bytes, 4-byte aligned)
# @outputs:     state[0..15] ^= round_key[0..15]
# @clobbers:    t0, t1
# @preserves:   sp, gp, ra, a0, a1, all callee-saved
# @stack:       0
# @cycles:      bounded (16: 4 unrolled word-XOR triples + ret)
# @ct:          required
# @spec:        FIPS 197 §5.1.4 (AddRoundKey)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes_addroundkey.py
# @tests:       tests/crypto/aes/test_aes_addroundkey.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* state ^= round_key, four 32-bit XORs.  Both buffers must be 4-byte
 * aligned (state always lives in aes_block_buf or a caller buffer
 * that is itself aligned; round_key is offset into aes_round_keys).
 *
 * Constant-time by construction: data-oblivious, no branches, only
 * register-to-register and fixed-offset memory ops.
 */

        .include "aes.S"

        .section .text.aes_addroundkey, "ax", @progbits
        .global aes_addroundkey
        .type   aes_addroundkey, @function
aes_addroundkey:
        lw      t0, 0(a0)
        lw      t1, 0(a1)
        xor     t0, t0, t1
        sw      t0, 0(a0)

        lw      t0, 4(a0)
        lw      t1, 4(a1)
        xor     t0, t0, t1
        sw      t0, 4(a0)

        lw      t0, 8(a0)
        lw      t1, 8(a1)
        xor     t0, t0, t1
        sw      t0, 8(a0)

        lw      t0, 12(a0)
        lw      t1, 12(a1)
        xor     t0, t0, t1
        sw      t0, 12(a0)

        ret

        .size   aes_addroundkey, . - aes_addroundkey
