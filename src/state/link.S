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
        .size link_table, LINK_TABLE_SIZE

        .balign 4
        .global link_session_scratch
        .type   link_session_scratch, @object
link_session_scratch:
        .skip LINK_SESSION_PADDED_MAX
        .size link_session_scratch, LINK_SESSION_PADDED_MAX
