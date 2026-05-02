# ============================================================================
# @function:    aes_invsubbytes
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes)
# @outputs:     state[i] = aes_invsbox(state[i]) for i in 0..15
# @clobbers:    t0..t6, a0..a7, ra
# @preserves:   sp, gp, s0..s11 (s0, s1 saved/restored)
# @stack:       16
# @cycles:      bounded (16 * aes_invsbox + loop overhead, ~6300)
# @ct:          required
# @spec:        FIPS 197 §5.3.2 (InvSubBytes)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw
# @tests:       tests/crypto/aes/test_aes_subbytes.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

        .include "aes.S"

        .section .text.aes_invsubbytes, "ax", @progbits
        .global aes_invsubbytes
        .type   aes_invsubbytes, @function
aes_invsubbytes:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)
        sw      s1, 4(sp)

        mv      s0, a0
        addi    s1, a0, AES_BLOCK_SIZE

.Lisbb_loop:
        lbu     a0, 0(s0)
        call    aes_invsbox
        sb      a0, 0(s0)
        addi    s0, s0, 1
        bltu    s0, s1, .Lisbb_loop

        lw      ra, 12(sp)
        lw      s0, 8(sp)
        lw      s1, 4(sp)
        addi    sp, sp, 16
        ret

        .size   aes_invsubbytes, . - aes_invsubbytes
