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
