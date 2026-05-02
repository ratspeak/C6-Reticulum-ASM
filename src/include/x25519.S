/* X25519 field representation — 10 signed int32 limbs, radix 2^25.5
 * (curve25519-donna 32-bit form). See docs/design/x25519-field.md for
 * the per-limb bit weights and the rationale.
 *
 * A field element occupies 40 bytes (10 × 4) in memory, 4-byte aligned.
 * Limbs are signed: arithmetic may produce intermediate negative
 * values that subsequent reduction folds back into the canonical range.
 */

        .equ X25519_FIELD_LIMBS,        10
        .equ X25519_FIELD_BYTES,        40      /* 10 × int32              */
        .equ X25519_WIRE_BYTES,         32      /* canonical packed form    */
        .equ X25519_SCALAR_BYTES,       32      /* clamped scalar bytes     */
