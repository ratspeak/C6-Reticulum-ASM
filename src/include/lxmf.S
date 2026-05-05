/* Milestone-9 LXMF constants. */

        .include "config.S"

        .equ LXMF_OK,                              0
        .equ LXMF_ERR_INVAL,                     -1
        .equ LXMF_ERR_OVERFLOW,                  -2
        .equ LXMF_ERR_MISSING,                   -3
        .equ LXMF_ERR_IO,                        -4
        .equ LXMF_ERR_BAD_SIGNATURE,             -5
        .equ LXMF_ERR_SHORT,                     -6
        .equ LXMF_ERR_UNKNOWN_SOURCE,            -7
        .equ LXMF_ERR_CAPACITY,                  -8
        .equ LXMF_ERR_NO_LINK,                   -9
        .equ LXMF_STATUS_DUPLICATE,               1

        .equ LXMF_DISPATCH_MODE_DIRECT,           0
        .equ LXMF_DISPATCH_MODE_OPPORTUNISTIC,    1

        .equ LXMF_HASH_SIZE,                     16
        .equ LXMF_MESSAGE_ID_SIZE,               32
        .equ LXMF_SIGNATURE_SIZE,                64
        .equ LXMF_TIMESTAMP_SIZE,                8
        .equ LXMF_STRUCT_OVERHEAD,               8
        .equ LXMF_OVERHEAD,                      (2 * LXMF_HASH_SIZE) + LXMF_SIGNATURE_SIZE + LXMF_TIMESTAMP_SIZE + LXMF_STRUCT_OVERHEAD

        .equ LXMF_MSGPACK_FIXARRAY2,             0x92
        .equ LXMF_MSGPACK_FIXARRAY4,             0x94
        .equ LXMF_MSGPACK_FIXARRAY5,             0x95
        .equ LXMF_MSGPACK_NIL,                   0xC0
        .equ LXMF_MSGPACK_BIN8,                  0xC4
        .equ LXMF_MSGPACK_FLOAT64,               0xCB
        .equ LXMF_MSGPACK_UINT8,                 0xCC

        .equ LXMF_PAYLOAD_MAX_TITLE,             64
        .equ LXMF_PAYLOAD_MAX_CONTENT,           255
        .equ LXMF_PAYLOAD_MAX_FIELDS,            64
        .equ LXMF_PAYLOAD_MAX_LEN,               397
        .equ LXMF_SIGNING_PREFIX_SIZE,           (2 * LXMF_HASH_SIZE)
        .equ LXMF_SIGNING_MAX_LEN,               LXMF_SIGNING_PREFIX_SIZE + LXMF_PAYLOAD_MAX_LEN + LXMF_MESSAGE_ID_SIZE
        .equ LXMF_PACKED_PREFIX_SIZE,            LXMF_SIGNING_PREFIX_SIZE + LXMF_SIGNATURE_SIZE
        .equ LXMF_PACKED_MAX_LEN,                LXMF_PACKED_PREFIX_SIZE + LXMF_PAYLOAD_MAX_LEN
        .equ LXMF_STAMP_MAX_LEN,                 32
        .equ LXMF_PAYLOAD_MAX_STAMPED_LEN,       LXMF_PAYLOAD_MAX_LEN + 2 + LXMF_STAMP_MAX_LEN
        .equ LXMF_PACKED_MAX_STAMPED_LEN,        LXMF_PACKED_PREFIX_SIZE + LXMF_PAYLOAD_MAX_STAMPED_LEN
        .equ LXMF_PAYLOAD_PARSED_HAS_STAMP,      1

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

        /* lxmf_payload_parsed_t struct offsets.
         *
         * payload_without_stamp points at raw input for array4 payloads. For
         * array5 payloads it points at the embedded no-stamp buffer, where the
         * first byte is normalised from fixarray5 to fixarray4 and the fifth
         * stamp element is omitted.
         */
        .equ LXMF_PAYLOAD_PARSED_OFF_RAW_PTR,                0
        .equ LXMF_PAYLOAD_PARSED_OFF_RAW_LEN,                4
        .equ LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR,      8
        .equ LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN,      12
        .equ LXMF_PAYLOAD_PARSED_OFF_TIMESTAMP_BE_PTR,       16
        .equ LXMF_PAYLOAD_PARSED_OFF_TITLE_PTR,              20
        .equ LXMF_PAYLOAD_PARSED_OFF_TITLE_LEN,              24
        .equ LXMF_PAYLOAD_PARSED_OFF_CONTENT_PTR,            28
        .equ LXMF_PAYLOAD_PARSED_OFF_CONTENT_LEN,            32
        .equ LXMF_PAYLOAD_PARSED_OFF_FIELDS_PTR,             36
        .equ LXMF_PAYLOAD_PARSED_OFF_FIELDS_LEN,             40
        .equ LXMF_PAYLOAD_PARSED_OFF_STAMP_PTR,              44
        .equ LXMF_PAYLOAD_PARSED_OFF_STAMP_LEN,              48
        .equ LXMF_PAYLOAD_PARSED_OFF_FLAGS,                  52
        .equ LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_BUF,      56
        .equ LXMF_PAYLOAD_PARSED_T_SIZE,                     456

        /* lxmf_message_parsed_t struct offsets.
         *
         * The fixed views point into the inbound packed message. The embedded
         * payload parser struct owns the no-stamp copy buffer used when a fifth
         * LXMF stamp element is present.
         */
        .equ LXMF_MESSAGE_PARSED_OFF_DEST_HASH_PTR,           0
        .equ LXMF_MESSAGE_PARSED_OFF_SOURCE_HASH_PTR,         4
        .equ LXMF_MESSAGE_PARSED_OFF_SIGNATURE_PTR,           8
        .equ LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PTR,             12
        .equ LXMF_MESSAGE_PARSED_OFF_PAYLOAD_LEN,             16
        .equ LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_PTR,       20
        .equ LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_LEN,       24
        .equ LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID,              28
        .equ LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PARSED,          60
        .equ LXMF_MESSAGE_PARSED_T_SIZE,                      LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PARSED + LXMF_PAYLOAD_PARSED_T_SIZE

        /* Upstream LXMF delivery announce app-data:
         * msgpack([display_name_or_nil, stamp_cost_or_nil]).
         * Display names are encoded as bin8, so 255 bytes is the hard cap.
         */
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_NAME,    255
        .equ LXMF_DELIVERY_ANNOUNCE_MAX_LEN,     260
