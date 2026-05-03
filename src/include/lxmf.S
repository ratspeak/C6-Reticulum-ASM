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
        .equ LXMF_MSGPACK_FIXARRAY4,             0x94
        .equ LXMF_MSGPACK_NIL,                   0xC0
        .equ LXMF_MSGPACK_BIN8,                  0xC4
        .equ LXMF_MSGPACK_FLOAT64,               0xCB
        .equ LXMF_MSGPACK_UINT8,                 0xCC

        .equ LXMF_PAYLOAD_MAX_TITLE,             64
        .equ LXMF_PAYLOAD_MAX_CONTENT,           255
        .equ LXMF_PAYLOAD_MAX_FIELDS,            64
        .equ LXMF_PAYLOAD_MAX_LEN,               397

        /* lxmf_payload_input_t struct offsets (28 bytes total).
         *
         * The timestamp pointer references the exact 8 big-endian IEEE754 bytes
         * to place after msgpack float64 marker 0xCB. Keeping f64 conversion out
         * of this primitive lets tests pin exact upstream msgpack bytes without
         * requiring an F-extension or soft-float code in the C6 binary.
         */
        .equ LXMF_PAYLOAD_IN_OFF_TIMESTAMP_BE_PTR, 0
        .equ LXMF_PAYLOAD_IN_OFF_TITLE_PTR,        4
        .equ LXMF_PAYLOAD_IN_OFF_TITLE_LEN,        8
        .equ LXMF_PAYLOAD_IN_OFF_CONTENT_PTR,      12
        .equ LXMF_PAYLOAD_IN_OFF_CONTENT_LEN,      16
        .equ LXMF_PAYLOAD_IN_OFF_FIELDS_PTR,       20
        .equ LXMF_PAYLOAD_IN_OFF_FIELDS_LEN,       24
        .equ LXMF_PAYLOAD_IN_T_SIZE,               28

        /* Upstream LXMF delivery announce app-data:
         * msgpack([display_name_or_nil, stamp_cost_or_nil]).
         * Display names are encoded as bin8, so 255 bytes is the hard cap.
         */
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_NAME,    255
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_LEN,     260
