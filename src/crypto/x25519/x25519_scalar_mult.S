# ============================================================================
# @function:    x25519_scalar_mult
# @module:      crypto/x25519
# @inputs:      a0 = out bytes ptr  (32 bytes; canonical wire u-coordinate)
#               a1 = k_bytes ptr    (32 bytes; raw scalar — clamping happens
#                                    inside this function on a private copy)
#               a2 = u_bytes ptr    (32 bytes; wire u-coordinate; the high
#                                    bit is dropped implicitly during unpack)
# @outputs:     out_bytes = canonical 32-byte LE encoding of (k · P_u).x
#                           where P_u is the Montgomery curve point with
#                           x-coordinate u, per RFC 7748 §5.
# @clobbers:    t0..t6, a3..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       128
# @cycles:      bounded (≈ ladder + pack + unpack + clamp ≈ 4 × 10^6)
# @ct:          required
# @spec:        RFC 7748 §5: end-to-end X25519 wire-form scalar
#               multiplication. Steps: copy k to a private 32-byte
#               buffer; call decode_scalar to clamp in place; field-
#               unpack u_bytes (which drops bit 255 implicitly via
#               limb 9's 25-bit mask, satisfying the §5 u-mask); run
#               montgomery_ladder; field-pack the resulting field
#               element to canonical 32 wire bytes. Caller's k_bytes
#               and u_bytes buffers are not modified.
# @verify:      proofs/crypto/x25519/X25519.cry, proofs/crypto/x25519/x25519_scalar_mult.saw
# @tests:       tests/crypto/x25519/test_x25519_scalar_mult.py
#               (Tier C bridge: drives the asm under qemu-system-riscv32
#               on RFC 7748 §5.2 v1/v2 and §6.1 vectors with the raw
#               wire bytes — same KAT scope as the ladder test but
#               exercising the full pipeline.)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack layout (128 bytes, 16-byte aligned):
 *   sp +  0 .. sp + 31:  scratch_k  (clamped scalar copy)
 *   sp + 32 .. sp + 71:  u_limbs    (40 bytes; output of field_unpack)
 *   sp + 72 .. sp +111:  out_limbs  (40 bytes; output of ladder; input to pack)
 *   sp +112             saved ra
 *   sp +116             saved s0    (caller's out ptr)
 *   sp +120             saved s1    (caller's u_bytes ptr)
 *   sp +124..127        pad
 */

        .include "x25519.S"

        .equ SCRATCH_K, 0
        .equ U_LIMBS,   32
        .equ OUT_LIMBS, 72
        .equ FRAME,    128
        .equ RA_OFF,   112
        .equ S0_OFF,   116
        .equ S1_OFF,   120

        .section .text.x25519_scalar_mult, "ax", @progbits
        .global x25519_scalar_mult
        .type   x25519_scalar_mult, @function
x25519_scalar_mult:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a0                          /* save caller's out ptr  */
        mv      s1, a2                          /* save caller's u_bytes  */

        # Copy k_bytes (32 bytes) onto stack so we can clamp without
        # touching the caller's buffer.
        .irp i, 0, 4, 8, 12, 16, 20, 24, 28
        lw      t0, \i(a1)
        sw      t0, (\i + SCRATCH_K)(sp)
        .endr

        # Clamp the local scalar copy in place (RFC 7748 §5).
        addi    a0, sp, SCRATCH_K
        call    x25519_decode_scalar

        # u_limbs := field_unpack(u_bytes). field_unpack drops bit 255
        # implicitly via limb 9's 25-bit mask, so no separate u-mask is
        # required.
        addi    a0, sp, U_LIMBS
        mv      a1, s1
        call    x25519_field_unpack

        # out_limbs := ladder(scratch_k, u_limbs).
        addi    a0, sp, OUT_LIMBS
        addi    a1, sp, SCRATCH_K
        addi    a2, sp, U_LIMBS
        call    x25519_montgomery_ladder

        # out_bytes := field_pack(out_limbs).
        mv      a0, s0
        addi    a1, sp, OUT_LIMBS
        call    x25519_field_pack

        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   x25519_scalar_mult, . - x25519_scalar_mult
