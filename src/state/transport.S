/* Static milestone-5 transport path table (ADR-0002). */

        .include "transport.S"

        .section .bss.transport_path_table, "aw", @nobits

        .global transport_path_table
        .type   transport_path_table, @object
        .balign 4
transport_path_table:
        .zero   TRANSPORT_PATH_TABLE_SIZE
        .size   transport_path_table, TRANSPORT_PATH_TABLE_SIZE
