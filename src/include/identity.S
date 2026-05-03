/* Reticulum identity layout constants used by milestone 3.
 *
 * identity_t stores upstream-compatible private and public byte ranges:
 * private_key = x25519_private[32] || ed25519_seed[32]
 * public_key  = x25519_public[32]  || ed25519_public[32]
 *
 * The identity hash helper operates on the canonical public-key bytes:
 * x25519_public[32] || ed25519_public[32], then writes the first 16
 * bytes of SHA-256(public_key).
 */

        .equ IDENTITY_OFF_X25519_SK,   0
        .equ IDENTITY_OFF_ED25519_SK,  32
        .equ IDENTITY_OFF_X25519_PK,   64
        .equ IDENTITY_OFF_ED25519_PK,  96
        .equ IDENTITY_OFF_HASH,        128
        .equ IDENTITY_OFF_RESERVED,    144
        .equ IDENTITY_T_SIZE,          160

        .equ IDENTITY_PRIVATE_KEY_SIZE, 64
        .equ IDENTITY_PUBLIC_KEY_SIZE,  64
        .equ IDENTITY_HASH_SIZE,        16
        .equ IDENTITY_RESERVED_SIZE,    16

        .equ IDENTITY_OK,               0
        .equ IDENTITY_ERR_INVAL,        -1
        .equ IDENTITY_ERR_MISSING,      -2
        .equ IDENTITY_ERR_IO,           -3

        .equ IDENTITY_RECORD_MAGIC,     0x31444952  /* "RID1" little-endian */
        .equ IDENTITY_RECORD_VERSION,   1
        .equ IDENTITY_RECORD_FLAGS,     0
        .equ IDENTITY_RECORD_HEADER_LEN, 48
        .equ IDENTITY_RECORD_SIZE,      256
        .equ IDENTITY_RECORD_CHECKSUM_SIZE, 32

        .equ IDENTITY_RECORD_OFF_MAGIC,    0
        .equ IDENTITY_RECORD_OFF_VERSION,  4
        .equ IDENTITY_RECORD_OFF_FLAGS,    5
        .equ IDENTITY_RECORD_OFF_HEADER_LEN, 6
        .equ IDENTITY_RECORD_OFF_IDENTITY_LEN, 8
        .equ IDENTITY_RECORD_OFF_RESERVED, 12
        .equ IDENTITY_RECORD_OFF_CHECKSUM, 16
        .equ IDENTITY_RECORD_OFF_IDENTITY, 48
        .equ IDENTITY_RECORD_OFF_PADDING,  208
        .equ IDENTITY_RECORD_PADDING_SIZE, 48
