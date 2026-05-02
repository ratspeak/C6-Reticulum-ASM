# ============================================================================
# @function:    aes_invshiftrows
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes, 4-byte aligned)
# @outputs:     state permuted in place per FIPS 197 §5.3.1
# @clobbers:    t0..t5
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~45)
# @ct:          required
# @spec:        FIPS 197 §5.3.1 (InvShiftRows)
# @verify:      kat-only; covered end-to-end by aes256_decrypt_block KAT
# @tests:       tests/crypto/aes/test_aes_shiftrows.py
# @adrs:        0001, 0002, 0006
# @status:      tested
# ============================================================================

/* Inverse of ShiftRows: row r is rotated RIGHT by r positions.
 *
 * Per-byte source for the new state:
 *   new word 0: state[0]  state[13] state[10] state[7]
 *   new word 1: state[4]  state[1]  state[14] state[11]
 *   new word 2: state[8]  state[5]  state[2]  state[15]
 *   new word 3: state[12] state[9]  state[6]  state[3]
 */

        .include "aes.S"

        .section .text.aes_invshiftrows, "ax", @progbits
        .global aes_invshiftrows
        .type   aes_invshiftrows, @function
aes_invshiftrows:
        /* nw0 = state[0] | state[13]<<8 | state[10]<<16 | state[7]<<24 */
        lbu     t0, 0(a0)
        lbu     t5, 13(a0)
        slli    t5, t5, 8
        or      t0, t0, t5
        lbu     t5, 10(a0)
        slli    t5, t5, 16
        or      t0, t0, t5
        lbu     t5, 7(a0)
        slli    t5, t5, 24
        or      t0, t0, t5

        /* nw1 = state[4] | state[1]<<8 | state[14]<<16 | state[11]<<24 */
        lbu     t1, 4(a0)
        lbu     t5, 1(a0)
        slli    t5, t5, 8
        or      t1, t1, t5
        lbu     t5, 14(a0)
        slli    t5, t5, 16
        or      t1, t1, t5
        lbu     t5, 11(a0)
        slli    t5, t5, 24
        or      t1, t1, t5

        /* nw2 = state[8] | state[5]<<8 | state[2]<<16 | state[15]<<24 */
        lbu     t2, 8(a0)
        lbu     t5, 5(a0)
        slli    t5, t5, 8
        or      t2, t2, t5
        lbu     t5, 2(a0)
        slli    t5, t5, 16
        or      t2, t2, t5
        lbu     t5, 15(a0)
        slli    t5, t5, 24
        or      t2, t2, t5

        /* nw3 = state[12] | state[9]<<8 | state[6]<<16 | state[3]<<24 */
        lbu     t3, 12(a0)
        lbu     t5, 9(a0)
        slli    t5, t5, 8
        or      t3, t3, t5
        lbu     t5, 6(a0)
        slli    t5, t5, 16
        or      t3, t3, t5
        lbu     t5, 3(a0)
        slli    t5, t5, 24
        or      t3, t3, t5

        sw      t0, 0(a0)
        sw      t1, 4(a0)
        sw      t2, 8(a0)
        sw      t3, 12(a0)
        ret

        .size   aes_invshiftrows, . - aes_invshiftrows
