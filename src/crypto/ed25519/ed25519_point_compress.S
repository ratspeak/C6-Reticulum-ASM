# ============================================================================
# @function:    ed25519_point_compress
# @module:      crypto/ed25519
# @inputs:      a0 = out_bytes ptr (32 bytes; encoded point)
#               a1 = P ptr (160 bytes; extended coords X, Y, Z, T)
# @outputs:     out_bytes = 32-byte RFC 8032 §5.1.2 encoding of P:
#                 - Compute affine x = X/Z, y = Y/Z
#                 - Bytes 0..30: y as LE 256-bit integer (255 low bits)
#                 - Bit 7 of byte 31: sign bit of x = x mod 2 (LSB)
#                 - Bits 0..6 of byte 31: high 7 bits of y
# @clobbers:    t0..t6, a2..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       176
# @cycles:      bounded (≈ field_inv (~400K) + 2 field_mul + 2 field_pack)
# @ct:          required (Z_inv via field_inv is already CT)
# @spec:        RFC 8032 §5.1.2 (encoding)
# @verify:      kat-only; the QEMU pytest exercises:
#                 - identity point (X=0, Y=1, Z=1, T=0) → 0x01,0x00,...,0x00
#                 - base point B → RFC 8032 §5.1.5 expected encoding
#                 - decompress(compress(P)) = P (round trip via separate
#                   pytest once point_decompress lands)
# @tests:       tests/crypto/ed25519/test_ed25519_point_compress.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (176 bytes, 16-byte aligned):
 *      0..39    Z_inv_limbs
 *     40..79    x_limbs        (X * Z_inv)
 *     80..119   y_limbs        (Y * Z_inv)
 *    120..151   x_bytes        (32 bytes; only the LSB matters for the sign)
 *    152..159   pad
 *    160..163   s1             (P ptr)
 *    164..167   s0             (out_bytes ptr)
 *    168..171   ra
 *    172..175   pad
 */

        .include "x25519.S"
        .include "ed25519.S"

        .equ Z_INV_OFF,   0
        .equ X_LIMBS_OFF, 40
        .equ Y_LIMBS_OFF, 80
        .equ X_BYTES_OFF, 120
        .equ S1_OFF,      160
        .equ S0_OFF,      164
        .equ RA_OFF,      168
        .equ FRAME,       176

        .equ PT_X, 0
        .equ PT_Y, 40
        .equ PT_Z, 80

        .section .text.ed25519_point_compress, "ax", @progbits
        .global ed25519_point_compress
        .type   ed25519_point_compress, @function
ed25519_point_compress:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a0                          /* out_bytes              */
        mv      s1, a1                          /* P                      */

        # Z_inv := Z^(-1)
        addi    a0, sp, Z_INV_OFF
        addi    a1, s1, PT_Z
        call    x25519_field_inv

        # x_limbs := X * Z_inv
        addi    a0, sp, X_LIMBS_OFF
        addi    a1, s1, PT_X
        addi    a2, sp, Z_INV_OFF
        call    x25519_field_mul

        # y_limbs := Y * Z_inv
        addi    a0, sp, Y_LIMBS_OFF
        addi    a1, s1, PT_Y
        addi    a2, sp, Z_INV_OFF
        call    x25519_field_mul

        # out_bytes := pack(y_limbs)  (32 bytes; high bit of byte 31 will be 0)
        mv      a0, s0
        addi    a1, sp, Y_LIMBS_OFF
        call    x25519_field_pack

        # x_bytes := pack(x_limbs)
        addi    a0, sp, X_BYTES_OFF
        addi    a1, sp, X_LIMBS_OFF
        call    x25519_field_pack

        # Set bit 7 of out_bytes[31] from LSB of x_bytes[0].
        lbu     t0, X_BYTES_OFF(sp)
        andi    t0, t0, 1
        slli    t0, t0, 7                        /* shift to bit 7        */
        lbu     t1, 31(s0)
        or      t1, t1, t0
        sb      t1, 31(s0)

        lw      ra, RA_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_point_compress, . - ed25519_point_compress
