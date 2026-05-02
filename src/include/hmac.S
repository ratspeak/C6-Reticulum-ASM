/* HMAC-SHA-256 layout constants per RFC 2104.
 *
 * The state buffers live in src/state/hmac.S; this header just makes
 * the sizes available to anyone that needs to allocate their own.
 */

        .equ HMAC_BLOCK_SIZE,       64      /* SHA-256 block size       */
        .equ HMAC_TAG_SIZE,         32      /* SHA-256 output size       */
        .equ HMAC_IPAD_BYTE,        0x36
        .equ HMAC_OPAD_BYTE,        0x5C
        .equ HMAC_IPAD_XOR_OPAD,    0x6A    /* 0x36 ^ 0x5C — flips between */
