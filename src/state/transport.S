/* Static milestone-5 transport path table (ADR-0002). */

        .include "transport.S"

        .section .bss.transport_path_table, "aw", @nobits

        .global transport_path_table
        .type   transport_path_table, @object
        .balign 4
transport_path_table:
        .zero   TRANSPORT_PATH_TABLE_SIZE
        .size   transport_path_table, TRANSPORT_PATH_TABLE_SIZE

        .section .bss.transport_packet_hashes, "aw", @nobits

        .global transport_packet_hashes
        .type   transport_packet_hashes, @object
        .balign 4
transport_packet_hashes:
        .zero   TRANSPORT_PACKET_HASH_TABLE_SIZE
        .size   transport_packet_hashes, TRANSPORT_PACKET_HASH_TABLE_SIZE

        .global transport_packet_hash_count
        .type   transport_packet_hash_count, @object
        .balign 4
transport_packet_hash_count:
        .zero   4
        .size   transport_packet_hash_count, 4

        .global transport_packet_hash_next
        .type   transport_packet_hash_next, @object
        .balign 4
transport_packet_hash_next:
        .zero   4
        .size   transport_packet_hash_next, 4
