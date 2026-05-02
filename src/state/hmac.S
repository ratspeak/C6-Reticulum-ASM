# Mutable state for HMAC-SHA-256 (per ADR-0002).
#
# Two buffers:
#   hmac_key_prep[64]  — prepared key (K′), XOR-flipped in place between
#                        the inner and outer hashes
#   hmac_inner_tag[32] — intermediate digest from the inner SHA-256

        .include "hmac.S"

        .section .bss.hmac_key_prep, "aw", @nobits
        .global hmac_key_prep
        .balign 4
hmac_key_prep:  .skip HMAC_BLOCK_SIZE

        .section .bss.hmac_inner_tag, "aw", @nobits
        .global hmac_inner_tag
        .balign 4
hmac_inner_tag: .skip HMAC_TAG_SIZE
