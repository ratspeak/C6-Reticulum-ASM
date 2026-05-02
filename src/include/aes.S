/* ============================================================================
 * AES-256 layout & sizing constants — shared across crypto/aes.
 *
 * AES-256 (FIPS 197): 128-bit block, 256-bit key, 14 rounds. Fifteen 16-byte
 * round keys: round_keys[15][16] = 240 bytes total. The state is a 4x4 column-
 * major byte matrix.
 *
 * Constant-time policy (ADR-0006): every S-box invocation uses the
 * Boyar-Peralta combinational circuit. No table lookups indexed by secret
 * bytes; no data-dependent branches. The MixColumns xtime helper is a
 * bit-mask + XOR (no multiplication table).
 * ============================================================================
 */

        .equ AES_BLOCK_SIZE,        16
        .equ AES_BLOCK_BITS,        128
        .equ AES_NB,                4         /* state columns */

        /* AES-256 specifics */
        .equ AES256_KEY_SIZE,       32
        .equ AES256_NK,             8         /* key columns */
        .equ AES256_NR,             14        /* number of rounds */
        .equ AES256_ROUND_KEYS,     15        /* NR + 1 */
        .equ AES256_RK_BYTES,       240       /* 15 * 16 */

        /* xtime polynomial reduction byte: (b<<1) ^ (msb? 0x1B : 0) */
        .equ AES_GF_MOD_BYTE,       0x1B
