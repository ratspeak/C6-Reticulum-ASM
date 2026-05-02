# ============================================================================
# @function:    aes_subword
# @module:      crypto/aes
# @inputs:      a0 = input word (4 packed bytes, little-endian)
# @outputs:     a0 = each byte mapped through aes_sbox, repacked
# @clobbers:    t0..t6, a1..a7, ra
# @preserves:   sp, gp, s0..s11
# @stack:       16
# @cycles:      bounded (~1400; 4 * aes_sbox + glue)
# @ct:          required (4 fixed aes_sbox calls; no data branches)
# @spec:        FIPS 197 §5.2 (SubWord; helper used by key expansion)
# @verify:      kat-only; covered end-to-end by aes256_key_expand KAT
# @tests:       tests/crypto/aes/test_aes_subword.py
# @adrs:        0001, 0002, 0006
# @status:      tested
# ============================================================================

/* AES SubWord: apply aes_sbox to each of the 4 bytes of a 32-bit word.
 * Used by key expansion. The input word is spilled to stack and each
 * byte is read with lbu (little-endian byte 0 at offset 0). The four
 * sbox results are written into a separate 4-byte stack slot, then
 * loaded back as a single word.
 */

        .include "aes.S"

        .section .text.aes_subword, "ax", @progbits
        .global aes_subword
        .type   aes_subword, @function
aes_subword:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      a0, 8(sp)               /* spill input word at 8..11 */

        lbu     a0, 8(sp)
        call    aes_sbox
        sb      a0, 4(sp)

        lbu     a0, 9(sp)
        call    aes_sbox
        sb      a0, 5(sp)

        lbu     a0, 10(sp)
        call    aes_sbox
        sb      a0, 6(sp)

        lbu     a0, 11(sp)
        call    aes_sbox
        sb      a0, 7(sp)

        lw      a0, 4(sp)               /* assembled output word */
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   aes_subword, . - aes_subword
