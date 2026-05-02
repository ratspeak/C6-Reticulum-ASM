# ============================================================================
# @function:    aes_shiftrows
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes, 4-byte aligned)
# @outputs:     state permuted in place per FIPS 197 §5.1.2
# @clobbers:    t0..t5
# @preserves:   sp, gp, ra, a0, all callee-saved
# @stack:       0
# @cycles:      bounded (~45)
# @ct:          required (no data-dependent control flow or addresses)
# @spec:        FIPS 197 §5.1.2 (ShiftRows)
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw, proofs/crypto/aes/aes_shiftrows.py
# @tests:       tests/crypto/aes/test_aes_shiftrows.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* AES ShiftRows: row r is rotated left by r positions in the state's
 * 4x4 byte matrix.  The state lives in column-major linear form, so
 * byte at (row, col) is at offset 4*col + row.
 *
 * Per-byte source for the new state (in the new column-major form):
 *   new word 0: state[0]  state[5]  state[10] state[15]
 *   new word 1: state[4]  state[9]  state[14] state[3]
 *   new word 2: state[8]  state[13] state[2]  state[7]
 *   new word 3: state[12] state[1]  state[6]  state[11]
 *
 * Each word is assembled into a register before any store, so the
 * source bytes that the next column needs are not clobbered first.
 */

        .include "aes.S"

        .section .text.aes_shiftrows, "ax", @progbits
        .global aes_shiftrows
        .type   aes_shiftrows, @function
aes_shiftrows:
        /* nw0 = state[0] | state[5]<<8 | state[10]<<16 | state[15]<<24 */
        lbu     t0, 0(a0)
        lbu     t5, 5(a0)
        slli    t5, t5, 8
        or      t0, t0, t5
        lbu     t5, 10(a0)
        slli    t5, t5, 16
        or      t0, t0, t5
        lbu     t5, 15(a0)
        slli    t5, t5, 24
        or      t0, t0, t5

        /* nw1 = state[4] | state[9]<<8 | state[14]<<16 | state[3]<<24 */
        lbu     t1, 4(a0)
        lbu     t5, 9(a0)
        slli    t5, t5, 8
        or      t1, t1, t5
        lbu     t5, 14(a0)
        slli    t5, t5, 16
        or      t1, t1, t5
        lbu     t5, 3(a0)
        slli    t5, t5, 24
        or      t1, t1, t5

        /* nw2 = state[8] | state[13]<<8 | state[2]<<16 | state[7]<<24 */
        lbu     t2, 8(a0)
        lbu     t5, 13(a0)
        slli    t5, t5, 8
        or      t2, t2, t5
        lbu     t5, 2(a0)
        slli    t5, t5, 16
        or      t2, t2, t5
        lbu     t5, 7(a0)
        slli    t5, t5, 24
        or      t2, t2, t5

        /* nw3 = state[12] | state[1]<<8 | state[6]<<16 | state[11]<<24 */
        lbu     t3, 12(a0)
        lbu     t5, 1(a0)
        slli    t5, t5, 8
        or      t3, t3, t5
        lbu     t5, 6(a0)
        slli    t5, t5, 16
        or      t3, t3, t5
        lbu     t5, 11(a0)
        slli    t5, t5, 24
        or      t3, t3, t5

        sw      t0, 0(a0)
        sw      t1, 4(a0)
        sw      t2, 8(a0)
        sw      t3, 12(a0)
        ret

        .size   aes_shiftrows, . - aes_shiftrows
