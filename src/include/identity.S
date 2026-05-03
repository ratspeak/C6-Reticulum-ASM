/* Reticulum identity layout constants used by milestone 3.
 *
 * The identity hash helper operates on the canonical public-key bytes:
 * x25519_public[32] || ed25519_public[32], then writes the first 16
 * bytes of SHA-256(public_key).
 */

        .equ IDENTITY_PUBLIC_KEY_SIZE,  64
        .equ IDENTITY_HASH_SIZE,        16

