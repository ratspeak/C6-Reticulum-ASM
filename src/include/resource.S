/* Milestone-7 resource/channel constants. */

        .include "link.S"

        .equ RESOURCE_OK,                         0
        .equ RESOURCE_ERR_INVAL,                 -1
        .equ RESOURCE_ERR_OVERFLOW,              -2

        .equ RESOURCE_HASH_SIZE,                  32
        .equ RESOURCE_RANDOM_HASH_SIZE,           4
        .equ RESOURCE_MAPHASH_SIZE,               4

        .equ CHANNEL_ENVELOPE_HEADER_LEN,         6
        .equ CHANNEL_ENVELOPE_MAX_PAYLOAD,        LINK_SESSION_PLAINTEXT_MAX - CHANNEL_ENVELOPE_HEADER_LEN
        .equ CHANNEL_ENVELOPE_MAX_RAW_LEN,        LINK_SESSION_PLAINTEXT_MAX

        /* channel_envelope_t struct offsets (20 bytes total). */
        .equ CHANNEL_ENV_OFF_RAW_LEN,             0
        .equ CHANNEL_ENV_OFF_MSGTYPE,             4
        .equ CHANNEL_ENV_OFF_SEQUENCE,            8
        .equ CHANNEL_ENV_OFF_PAYLOAD_LEN,         12
        .equ CHANNEL_ENV_OFF_PAYLOAD_PTR,         16
        .equ CHANNEL_ENV_T_SIZE,                  20

        .equ RESOURCE_REASSEMBLY_CAPACITY,        2
        .equ RESOURCE_REASSEMBLY_MAX_PARTS,       64
        .equ RESOURCE_REASM_BITMAP_BYTES,         RESOURCE_REASSEMBLY_MAX_PARTS / 8
        .equ RESOURCE_REASM_HASHMAP_BYTES,        RESOURCE_REASSEMBLY_MAX_PARTS * RESOURCE_MAPHASH_SIZE
        .equ RESOURCE_REASM_WINDOW_MIN,           2
        .equ RESOURCE_REASM_WINDOW_INIT,          4
        .equ RESOURCE_REASM_WINDOW_MAX,           75

        .equ RESOURCE_REASM_STATUS_EMPTY,         0
        .equ RESOURCE_REASM_STATUS_RECEIVING,     1
        .equ RESOURCE_REASM_STATUS_COMPLETE,      2

        /* resource_reassembly_entry_t offsets (316 bytes total). */
        .equ RESOURCE_REASM_OFF_VALID,            0
        .equ RESOURCE_REASM_OFF_STATUS,           1
        .equ RESOURCE_REASM_OFF_WINDOW,           2
        .equ RESOURCE_REASM_OFF_RESERVED,         3
        .equ RESOURCE_REASM_OFF_TOTAL_PARTS,      4
        .equ RESOURCE_REASM_OFF_RECEIVED_COUNT,   8
        .equ RESOURCE_REASM_OFF_CONSECUTIVE_IDX,  12
        .equ RESOURCE_REASM_OFF_RESOURCE_HASH,    16
        .equ RESOURCE_REASM_OFF_RANDOM_HASH,      48
        .equ RESOURCE_REASM_OFF_RECEIVED_BITMAP,  52
        .equ RESOURCE_REASM_OFF_HASHMAP,          60
        .equ RESOURCE_REASM_ENTRY_SIZE,           316
        .equ RESOURCE_REASM_TABLE_SIZE,           RESOURCE_REASSEMBLY_CAPACITY * RESOURCE_REASM_ENTRY_SIZE
