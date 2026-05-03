/* ============================================================================
 * Ed25519 statically allocated state (ADR-0002).
 *
 * The group order L (32 bytes, little-endian) and the base point B (in
 * extended-coordinate form) live here as rodata constants; per-call
 * scratch buffers (signature workspace, scalar buffers, point buffers)
 * are allocated on the caller's stack inside ed25519_sign / verify.
 *
 * No instructions live here.
 * ============================================================================
 */

        .include "ed25519.S"

        # ---- Group order L (RFC 8032 §5.1, hex little-endian) ----
        # L = 2^252 + 27742317777372353535851937790883648493
        # As 32 LE bytes (low byte first):
        #   0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        #   0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        #   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        #   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        .section .rodata.ed25519_L, "a"
        .global ed25519_L_bytes
        .type   ed25519_L_bytes, @object
        .balign 4
ed25519_L_bytes:
        .byte 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58
        .byte 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14
        .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        .size ed25519_L_bytes, 32

        # ---- Curve constant d = -121665/121666 mod p, in 10-limb radix-2^25.5 form
        .section .rodata.ed25519_d_limbs, "a"
        .global ed25519_d_limbs
        .balign 4
ed25519_d_limbs:
        .word 0x035978a3, 0x000d37284, 0x03156ebd, 0x0006a0a0e, 0x0001c029
        .word 0x0179e898, 0x03a03cbb, 0x001ce7198, 0x02e2b6ff, 0x01480db3
        .size ed25519_d_limbs, 40

        # ---- 2*d mod p, in 10-limb form
        .global ed25519_2d_limbs
        .balign 4
ed25519_2d_limbs:
        .word 0x02b2f159, 0x001a6e509, 0x022add7a, 0x000d4141d, 0x00038052
        .word 0x000f3d130, 0x03407977, 0x0019ce331, 0x01c56dff, 0x000901b67
        .size ed25519_2d_limbs, 40

        # ---- Base point B (RFC 8032 §5.1) in extended coords (X, Y, Z, T)
        # Bx = 0x216936d3...8f25d51a
        # By = 4/5 mod p = 0x6666...6658
        # Bz = 1
        # Bt = (Bx * By) mod p
        .global ed25519_base_point
        .balign 4
ed25519_base_point:
        # X
        .word 0x0325d51a, 0x0018b5823, 0x000f6592a, 0x00104a92d, 0x01a4b31d
        .word 0x001d6dc5c, 0x027118fe, 0x0007fd814, 0x013cd6e5, 0x0085a4db
        # Y
        .word 0x02666658, 0x001999999, 0x000cccccc, 0x001333333, 0x01999999
        .word 0x000666666, 0x03333333, 0x000cccccc, 0x02666666, 0x001999999
        # Z = 1
        .word 1, 0, 0, 0, 0, 0, 0, 0, 0, 0
        # T = X * Y mod p
        .word 0x01b7dda3, 0x001a2ace9, 0x025eadbb, 0x00003ba8a, 0x0083c27e
        .word 0x000abe37d, 0x01274732, 0x000ccacdd, 0x00fd78b7, 0x019e1d7c
        .size ed25519_base_point, 160
