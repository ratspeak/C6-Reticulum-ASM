/* ============================================================================
 * SHA-512 statically allocated state (ADR-0002).
 *
 * One singleton sha512_ctx for the QEMU dispatcher KAT plumbing and as
 * scratch for higher-level callers (notably ed25519). When several
 * concurrent SHA-512 streams are needed (e.g., ed25519_sign needs at
 * most one at a time, but ed25519_verify could chain), callers pass a
 * stack-allocated 208-byte ctx instead — the API takes a ctx pointer.
 *
 * No instructions live here.
 * ============================================================================
 */

        .include "sha512.S"

        .section .bss.sha512_ctx, "aw", @nobits
        .global sha512_ctx
        .type   sha512_ctx, @object
        .balign 8
sha512_ctx:
        .skip   SHA512_CTX_SIZE
        .size   sha512_ctx, SHA512_CTX_SIZE

        .section .bss.sha512_digest_buf, "aw", @nobits
        .global sha512_digest_buf
        .type   sha512_digest_buf, @object
        .balign 8
sha512_digest_buf:
        .skip   SHA512_DIGEST_SIZE
        .size   sha512_digest_buf, SHA512_DIGEST_SIZE
