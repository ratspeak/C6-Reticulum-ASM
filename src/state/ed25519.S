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
