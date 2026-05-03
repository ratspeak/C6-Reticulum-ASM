# ============================================================================
# @function:    aes_mixcolumns
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes)
# @outputs:     each 4-byte column is multiplied by the AES MDS matrix
#               (FIPS 197 §5.1.3) in place
# @clobbers:    t0..t6, a0..a4, ra
# @preserves:   sp, gp, s0, s1 (saved/restored), s2..s11
# @stack:       16
# @cycles:      bounded (~190; 4 column iterations of ~45 ops each)
# @ct:          required (xtime is branch-free; loop is data-independent)
# @spec:        FIPS 197 §5.1.3 (MixColumns) using the compact identity
#                 new_s_i = s_i ^ T ^ xtime(s_i ^ s_{i+1})
#               where T = s0 ^ s1 ^ s2 ^ s3 (column XOR sum) and indices
#               are taken mod 4. Constant-time xtime: msb extract → sign
#               mask → AND with 0x1B → XOR with (input<<1).
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes_mixcolumns.bsc, proofs/crypto/aes/aes_mixcolumns.py
# @tests:       tests/crypto/aes/test_aes_mixcolumns.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES MixColumns — apply the GF(2^8) MDS matrix to each of the four
 * 4-byte columns of the state.  The classical form is a matrix
 * multiplication with constants in {1, 2, 3}; we use the compact
 * identity above to avoid encoding the constant 3 (3*x = xtime(x) ^ x).
 *
 * GF(2^8) doubling (xtime) under reducing polynomial 0x11B, branch-
 * free:
 *
 *   msb_mask = -((x >> 7) & 1)        -- 0 or 0xFFFFFFFF
 *   poly     = msb_mask & 0x1B        -- 0 or 0x1B
 *   xt(x)    = ((x << 1) & 0xFF) ^ poly
 *
 * No data-dependent branch, no table lookup.  See ADR-0006.
 */

        .include "aes.S"

        .section .text.aes_mixcolumns, "ax", @progbits
        .global aes_mixcolumns
        .type   aes_mixcolumns, @function
aes_mixcolumns:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)

        mv      s0, a0                  /* column cursor */
        addi    s1, a0, AES_BLOCK_SIZE  /* end */

.Lmc_loop:
        /* Load the 4 column bytes into t0..t3. */
        lbu     t0, 0(s0)
        lbu     t1, 1(s0)
        lbu     t2, 2(s0)
        lbu     t3, 3(s0)

        /* T = b0 ^ b1 ^ b2 ^ b3 */
        xor     t4, t0, t1
        xor     t4, t4, t2
        xor     t4, t4, t3

        /* new b0 = b0 ^ T ^ xtime(b0 ^ b1) */
        xor     a0, t0, t1
        srli    a1, a0, 7
        neg     a1, a1
        andi    a1, a1, AES_GF_MOD_BYTE
        slli    a2, a0, 1
        andi    a2, a2, 0xff
        xor     a0, a2, a1
        xor     a0, a0, t0
        xor     a0, a0, t4
        sb      a0, 0(s0)

        /* new b1 = b1 ^ T ^ xtime(b1 ^ b2) */
        xor     a0, t1, t2
        srli    a1, a0, 7
        neg     a1, a1
        andi    a1, a1, AES_GF_MOD_BYTE
        slli    a2, a0, 1
        andi    a2, a2, 0xff
        xor     a0, a2, a1
        xor     a0, a0, t1
        xor     a0, a0, t4
        sb      a0, 1(s0)

        /* new b2 = b2 ^ T ^ xtime(b2 ^ b3) */
        xor     a0, t2, t3
        srli    a1, a0, 7
        neg     a1, a1
        andi    a1, a1, AES_GF_MOD_BYTE
        slli    a2, a0, 1
        andi    a2, a2, 0xff
        xor     a0, a2, a1
        xor     a0, a0, t2
        xor     a0, a0, t4
        sb      a0, 2(s0)

        /* new b3 = b3 ^ T ^ xtime(b3 ^ b0) */
        xor     a0, t3, t0
        srli    a1, a0, 7
        neg     a1, a1
        andi    a1, a1, AES_GF_MOD_BYTE
        slli    a2, a0, 1
        andi    a2, a2, 0xff
        xor     a0, a2, a1
        xor     a0, a0, t3
        xor     a0, a0, t4
        sb      a0, 3(s0)

        addi    s0, s0, 4
        bltu    s0, s1, .Lmc_loop

        lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   aes_mixcolumns, . - aes_mixcolumns
