# ============================================================================
# @function:    x25519_cswap
# @module:      crypto/x25519
# @inputs:      a0 = swap (0 or 1; high bits MUST be zero — caller's job)
#               a1 = a ptr (40 bytes; modified in place if swap == 1)
#               a2 = b ptr (40 bytes; modified in place if swap == 1)
# @outputs:     if swap == 1, a and b are exchanged; else unchanged
# @clobbers:    t0..t6, a0
# @preserves:   sp, gp, ra, a1, a2, all callee-saved
# @stack:       0
# @cycles:      bounded (~80; 10 unrolled lw/lw/xor/and/xor/xor/sw/sw)
# @ct:          required
# @spec:        RFC 7748 §5 — constant-time conditional swap via
#               mask(swap) = -swap (0 → 0x00000000, 1 → 0xFFFFFFFF).
#               Each limb: diff = (a^b) & mask; a ^= diff; b ^= diff.
# @verify:      proofs/crypto/x25519/X25519FieldOps.cry, proofs/crypto/x25519/x25519_cswap.saw, proofs/crypto/x25519/x25519_cswap.py
# @tests:       tests/crypto/x25519/test_x25519_cswap.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* x25519_cswap: constant-time conditional swap of two 40-byte buffers.
 *
 * mask = -swap (two's complement) gives 0 or 0xFFFFFFFF without any
 * branch on swap. Per limb: XOR-swap masked by mask. Branch-free,
 * memory access pattern independent of swap. */

        .include "x25519.S"

        .section .text.x25519_cswap, "ax", @progbits
        .global x25519_cswap
        .type   x25519_cswap, @function
x25519_cswap:
        sub     a0, zero, a0            /* mask = -swap                 */
        .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        lw      t0, (\i*4)(a1)
        lw      t1, (\i*4)(a2)
        xor     t2, t0, t1
        and     t2, t2, a0              /* diff = (a^b) & mask          */
        xor     t0, t0, t2
        xor     t1, t1, t2
        sw      t0, (\i*4)(a1)
        sw      t1, (\i*4)(a2)
        .endr
        ret

        .size   x25519_cswap, . - x25519_cswap
