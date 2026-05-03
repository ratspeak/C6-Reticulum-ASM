# ============================================================================
# @function:    aes_subbytes
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes)
# @outputs:     state[i] = aes_sbox(state[i]) for i in 0..15
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s11 (s0, s1 saved/restored across the loop)
# @stack:       16
# @cycles:      bounded (16 * aes_sbox + loop overhead, ~5500)
# @ct:          required (loop counter is data-independent; aes_sbox is CT)
# @spec:        FIPS 197 §5.1.1 (SubBytes — 16-cell map)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes_subbytes.bsc
# @tests:       tests/crypto/aes/test_aes_subbytes.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* SubBytes applies aes_sbox to each of the 16 state bytes.  The loop
 * counter is the address (s0) advanced from the base to base+16, so
 * the iteration count is structural (not data-dependent). */

        .include "aes.S"

        .section .text.aes_subbytes, "ax", @progbits
        .global aes_subbytes
        .type   aes_subbytes, @function
aes_subbytes:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)

        mv      s0, a0                  /* cursor */
        addi    s1, a0, AES_BLOCK_SIZE  /* end */

.Lsbb_loop:
        lbu     a0, 0(s0)
        call    aes_sbox
        sb      a0, 0(s0)
        addi    s0, s0, 1
        bltu    s0, s1, .Lsbb_loop

        lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   aes_subbytes, . - aes_subbytes
