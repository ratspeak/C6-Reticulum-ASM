/* Milestone-9 LXMF constants. */

        .include "config.S"

        .equ LXMF_OK,                              0
        .equ LXMF_ERR_INVAL,                     -1
        .equ LXMF_ERR_OVERFLOW,                  -2

        .equ LXMF_HASH_SIZE,                     16
        .equ LXMF_SIGNATURE_SIZE,                64
        .equ LXMF_TIMESTAMP_SIZE,                8
        .equ LXMF_STRUCT_OVERHEAD,               8
        .equ LXMF_OVERHEAD,                      (2 * LXMF_HASH_SIZE) + LXMF_SIGNATURE_SIZE + LXMF_TIMESTAMP_SIZE + LXMF_STRUCT_OVERHEAD

        .equ LXMF_MSGPACK_FIXARRAY2,             0x92
        .equ LXMF_MSGPACK_NIL,                   0xC0
        .equ LXMF_MSGPACK_BIN8,                  0xC4
        .equ LXMF_MSGPACK_UINT8,                 0xCC

        /* Upstream LXMF delivery announce app-data:
         * msgpack([display_name_or_nil, stamp_cost_or_nil]).
         * Display names are encoded as bin8, so 255 bytes is the hard cap.
         */
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_NAME,    255
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_LEN,     260
