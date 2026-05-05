/* Milestone-5 in-RAM transport path table constants. */

        .equ TRANSPORT_OK,                    0
        .equ TRANSPORT_STATUS_ACCEPTED,       0
        .equ TRANSPORT_STATUS_UPDATED,        1
        .equ TRANSPORT_STATUS_DUPLICATE,      2
        .equ TRANSPORT_STATUS_FORWARDED,      3
        .equ TRANSPORT_ERR_INVAL,            -1
        .equ TRANSPORT_ERR_NOT_FOUND,        -2

        .equ TRANSPORT_PATH_CAPACITY,         8
        .equ TRANSPORT_INTERFACE_KISS,        1
        .equ TRANSPORT_INTERFACE_LORA,        2

        .equ TRANSPORT_PACKET_HASH_SIZE,      16
        .equ TRANSPORT_PACKET_HASH_CAPACITY,  16
        .equ TRANSPORT_PACKET_HASH_TABLE_SIZE, 256

        .equ TRANSPORT_PATH_OFF_VALID,        0
        .equ TRANSPORT_PATH_OFF_INTERFACE,    1
        .equ TRANSPORT_PATH_OFF_HOPS,         2
        .equ TRANSPORT_PATH_OFF_RESERVED,     3
        .equ TRANSPORT_PATH_OFF_LAST_SEEN,    4
        .equ TRANSPORT_PATH_OFF_DEST_HASH,    8
        .equ TRANSPORT_PATH_OFF_IDENTITY_HASH, 24
        .equ TRANSPORT_PATH_OFF_PUBLIC_KEY,   40
        .equ TRANSPORT_PATH_OFF_NEXT_HOP,     104
        .equ TRANSPORT_PATH_ENTRY_SIZE,       120
        .equ TRANSPORT_PATH_TABLE_SIZE,       960
