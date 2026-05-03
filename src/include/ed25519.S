/* Ed25519 layout constants per RFC 8032.
 *
 * Curve: edwards25519, twisted Edwards form of Curve25519:
 *   -x² + y² = 1 + d·x²·y²   over F_p where p = 2^255 - 19
 *   d = -121665/121666 mod p
 *
 * Group order:
 *   L = 2^252 + 27742317777372353535851937790883648493
 *
 * Wire encodings:
 *   - public key  : 32 bytes, encoded little-endian; bit 255 carries
 *                   the sign of x.
 *   - signature   : 64 bytes = R (32, encoded point) || s (32, scalar LE).
 *   - private key : 32-byte seed (the secret bytes the user keeps).
 */

        .equ ED25519_PUB_BYTES,         32
        .equ ED25519_PRIV_BYTES,        32
        .equ ED25519_SIG_BYTES,         64
        .equ ED25519_SCALAR_BYTES,      32
        .equ ED25519_FIELD_BYTES,       40   /* radix-2^25.5 limbs       */
