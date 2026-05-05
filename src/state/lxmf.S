/* Static milestone-9 LXMF inbound slot state (ADR-0002). */

        .include "lxmf.S"

        .section .bss.lxmf_inbound, "aw", @nobits

        .global lxmf_inbound_slot_valid
        .type   lxmf_inbound_slot_valid, @object
        .balign 4
lxmf_inbound_slot_valid:
        .zero   4
        .size   lxmf_inbound_slot_valid, 4

        .global lxmf_inbound_message_id
        .type   lxmf_inbound_message_id, @object
        .balign 4
lxmf_inbound_message_id:
        .zero   LXMF_MESSAGE_ID_SIZE
        .size   lxmf_inbound_message_id, LXMF_MESSAGE_ID_SIZE

        .global lxmf_inbound_dest_hash
        .type   lxmf_inbound_dest_hash, @object
        .balign 4
lxmf_inbound_dest_hash:
        .zero   LXMF_HASH_SIZE
        .size   lxmf_inbound_dest_hash, LXMF_HASH_SIZE

        .global lxmf_inbound_source_hash
        .type   lxmf_inbound_source_hash, @object
        .balign 4
lxmf_inbound_source_hash:
        .zero   LXMF_HASH_SIZE
        .size   lxmf_inbound_source_hash, LXMF_HASH_SIZE

        .global lxmf_inbound_payload_len
        .type   lxmf_inbound_payload_len, @object
        .balign 4
lxmf_inbound_payload_len:
        .zero   4
        .size   lxmf_inbound_payload_len, 4
