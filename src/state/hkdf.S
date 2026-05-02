# Mutable state for HKDF-SHA-256 (per ADR-0002).
#
# hkdf_msg_buf is the scratch HMAC-input buffer (T(i-1) || info ||
# counter); hkdf_t_buf holds the current T(i) so it can become T(i-1)
# on the next iteration.
#
# An all-zero salt buffer (used by hkdf_extract when the caller passes
# an empty salt) lives in .rodata.

        .include "hkdf.S"

        .section .bss.hkdf_msg_buf, "aw", @nobits
        .global hkdf_msg_buf
        .balign 4
hkdf_msg_buf:   .skip HKDF_MSG_BUF_SIZE

        .section .bss.hkdf_t_buf, "aw", @nobits
        .global hkdf_t_buf
        .balign 4
hkdf_t_buf:     .skip HKDF_HASH_LEN

        .section .bss.hkdf_okm_buf, "aw", @nobits
        .global hkdf_okm_buf
        .balign 4
hkdf_okm_buf:   .skip 256

        .section .rodata.hkdf_zero_salt, "a"
        .global hkdf_zero_salt
        .balign 4
hkdf_zero_salt:
        .zero HKDF_HASH_LEN
