/* ============================================================================
 * X25519 statically allocated state (ADR-0002).
 *
 * Owned by crypto/x25519/*. Buffers for the QEMU-driven KAT harness — the
 * Montgomery ladder owns its own working buffers in stack frames during
 * scalar-mult, so this state is exclusively the test surface.
 *
 * No instructions live here.
 * ============================================================================
 */

        .include "x25519.S"

        .section .bss.x25519_field_buf, "aw", @nobits
        .global x25519_field_buf
        .type   x25519_field_buf, @object
        .balign 4
x25519_field_buf:
        .zero   X25519_FIELD_BYTES
        .size   x25519_field_buf, X25519_FIELD_BYTES

        # Curve25519 base-point u-coordinate = 9 (RFC 7748 §4.1).
        .section .rodata.x25519_base_point, "a"
        .global x25519_base_point
        .type   x25519_base_point, @object
        .balign 4
x25519_base_point:
        .byte   9
        .zero   31
        .size   x25519_base_point, 32
