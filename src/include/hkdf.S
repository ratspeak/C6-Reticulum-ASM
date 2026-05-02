/* HKDF-SHA-256 layout constants per RFC 5869.
 *
 * `hkdf_msg_buf` is the scratch buffer assembled for each iteration's
 * HMAC input — `T(i-1) || info || counter`. The 256-byte size caps the
 * info length at 256 - 32 - 1 = 223 bytes, well above any Reticulum
 * derivation label.
 */

        .equ HKDF_HASH_LEN,        32      /* SHA-256 output           */
        .equ HKDF_MSG_BUF_SIZE,    256
        .equ HKDF_MAX_INFO_LEN,    HKDF_MSG_BUF_SIZE - HKDF_HASH_LEN - 1
