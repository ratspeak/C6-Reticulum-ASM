# Mutable state for the SHA-256 streaming API. Per ADR-0002, all RAM is
# statically allocated; this is the singleton sha256_ctx buffer. Callers
# that need an independent context (e.g., HMAC's two parallel hashes)
# allocate a second buffer in their own state file.
#
# The H state is initialised at runtime by sha256_init; .bss leaves the
# buffer zeroed at boot.

        .include "sha256.S"

        .section .bss.sha256_ctx, "aw", @nobits
        .global sha256_ctx
        .balign 16
sha256_ctx:     .skip SHA256_CTX_SIZE

        .section .bss.sha256_digest_buf, "aw", @nobits
        .global sha256_digest_buf
        .balign 4
sha256_digest_buf:
        .skip SHA256_DIGEST_SIZE

        .section .rodata.sha256_iv, "a"
        .global sha256_iv
        .balign 4
sha256_iv:
        .word 0x6a09e667
        .word 0xbb67ae85
        .word 0x3c6ef372
        .word 0xa54ff53a
        .word 0x510e527f
        .word 0x9b05688c
        .word 0x1f83d9ab
        .word 0x5be0cd19
