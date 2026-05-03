/* Static milestone-7 resource receive state (ADR-0002). */

        .include "resource.S"

        .section .bss.resource_reassembly_table, "aw", @nobits
        .balign 4
        .global resource_reassembly_table
        .type   resource_reassembly_table, @object
resource_reassembly_table:
        .skip   RESOURCE_REASM_TABLE_SIZE
        .size   resource_reassembly_table, RESOURCE_REASM_TABLE_SIZE
