/* SHA-256 layout constants per FIPS 180-4 §5.
 *
 * Caller provides a `sha256_ctx` buffer (112 bytes, 16-byte aligned).
 * The streaming API (init / update / final) operates on this buffer via
 * the byte offsets defined here.
 *
 *   struct sha256_ctx {        // 112 bytes total
 *       uint32_t H[8];         // intermediate hash state           (offset 0)
 *       uint64_t length_bits;  // total bytes hashed × 8            (offset 32)
 *       uint8_t  block[64];    // partial block buffer              (offset 40)
 *       uint32_t block_len;    // bytes currently buffered in block (offset 104)
 *       uint32_t _pad;         // align total to 16 bytes           (offset 108)
 *   };
 */

        .equ SHA256_CTX_H,          0
        .equ SHA256_CTX_LEN_BITS,   32
        .equ SHA256_CTX_BLOCK,      40
        .equ SHA256_CTX_BLOCK_LEN,  104
        .equ SHA256_CTX_SIZE,       112

        .equ SHA256_BLOCK_SIZE,     64
        .equ SHA256_DIGEST_SIZE,    32
