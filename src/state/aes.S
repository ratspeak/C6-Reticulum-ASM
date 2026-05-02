/* ============================================================================
 * AES-256 statically allocated state (ADR-0002).
 *
 * Owned by crypto/aes/*. The buffers are sized for the largest single AES
 * working set (one expanded key schedule + one block); higher-level callers
 * (e.g. CBC chaining) supply their own input/output buffers.
 *
 * No instructions live here.
 * ============================================================================
 */

        .include "aes.S"

        .section .bss.aes_round_keys, "aw", @nobits
        .global aes_round_keys
        .type   aes_round_keys, @object
        .balign 4
aes_round_keys:
        .zero   AES256_RK_BYTES
        .size   aes_round_keys, AES256_RK_BYTES

        .section .bss.aes_block_buf, "aw", @nobits
        .global aes_block_buf
        .type   aes_block_buf, @object
        .balign 4
aes_block_buf:
        .zero   AES_BLOCK_SIZE
        .size   aes_block_buf, AES_BLOCK_SIZE

        .section .bss.aes_iv_buf, "aw", @nobits
        .global aes_iv_buf
        .type   aes_iv_buf, @object
        .balign 4
aes_iv_buf:
        .zero   AES_BLOCK_SIZE
        .size   aes_iv_buf, AES_BLOCK_SIZE
