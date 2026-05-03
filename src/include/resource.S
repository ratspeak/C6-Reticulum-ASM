/* Milestone-7 resource/channel constants. */

        .include "link.S"

        .equ RESOURCE_OK,                         0
        .equ RESOURCE_ERR_INVAL,                 -1
        .equ RESOURCE_ERR_OVERFLOW,              -2

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
