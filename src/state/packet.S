# Mutable state for the packet parser. Per ADR-0002, all RAM is
# statically allocated; the packet_t struct lives here so _main and
# (later) transport can populate it without allocation.

        .include "packet.S"

        .section .bss.packet_struct, "aw", @nobits
        .global packet_struct
packet_struct:  .skip PKT_T_SIZE
