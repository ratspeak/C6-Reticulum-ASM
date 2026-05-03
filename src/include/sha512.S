/* SHA-512 layout constants per FIPS 180-4 §5 / §6.4.
 *
 * Caller provides a `sha512_ctx` buffer (208 bytes, 16-byte aligned).
 * Streaming API (init / update / final) operates on this buffer via
 * the byte offsets defined here.
 *
 *   struct sha512_ctx {              // 208 bytes total
 *       uint64_t H[8];                // intermediate hash state    offset 0
 *       uint64_t length_bits;        // total bytes hashed × 8      offset 64
 *       uint8_t  block[128];         // partial block buffer        offset 72
 *       uint32_t block_len;          // bytes currently buffered    offset 200
 *       uint32_t _pad;               // align total to 16 bytes     offset 204
 *   };
 *
 * 64-bit fields (H[i], length_bits) are stored as two consecutive
 * 32-bit little-endian words on RV32: low word at offset, high word at
 * offset + 4. Inside the H[] state this matches the natural FIPS 180-4
 * H_i interpretation when paired with the BE-loaded message words —
 * see sha512_compress for the load convention.
 */

        .equ SHA512_CTX_H,          0       /* uint64_t H[8] (8×8 = 64) */
        .equ SHA512_CTX_LEN_BITS,   64      /* uint64_t length_bits     */
        .equ SHA512_CTX_BLOCK,      72      /* uint8_t block[128]       */
        .equ SHA512_CTX_BLOCK_LEN,  200     /* uint32_t block_len       */
        .equ SHA512_CTX_SIZE,       208

        .equ SHA512_BLOCK_SIZE,     128     /* bytes                    */
        .equ SHA512_DIGEST_SIZE,    64      /* bytes                    */
        .equ SHA512_ROUNDS,         80
