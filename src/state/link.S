/* Milestone-6 in-RAM link table.
 *
 * The table is zeroed by _init_bss at boot. A zero valid byte means the slot
 * is available; link_handshake_init and later handshake functions own all
 * mutation.
 */

        .include "link.S"

        .section .bss.link, "aw", @nobits
        .balign 4
        .global link_table
link_table:
        .skip LINK_TABLE_SIZE
