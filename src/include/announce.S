/* Reticulum announce constants for milestones 3 and 5.
 *
 * Non-ratchet HEADER_1 announce packet:
 *   flags[1] || hops[1] || destination_hash[16] || context[1] ||
 *   public_key[64] || name_hash[10] || random_hash[10] ||
 *   signature[64] || app_data
 *
 * Non-ratchet HEADER_2 transport announce packet:
 *   flags[1] || hops[1] || transport_id[16] || destination_hash[16] ||
 *   context[1] || public_key[64] || name_hash[10] || random_hash[10] ||
 *   signature[64] || app_data
 */

        .include "config.S"

        .equ ANNOUNCE_OK,                    0
        .equ ANNOUNCE_ERR_INVAL,            -1

        .equ ANNOUNCE_HEADER_FLAGS,          0x01
        .equ ANNOUNCE_HEADER2_FLAGS,         0x51
        .equ ANNOUNCE_HEADER_HOPS,           0x00
        .equ ANNOUNCE_CONTEXT_NONE,          0x00

        .equ ANNOUNCE_HEADER_LEN,            19
        .equ ANNOUNCE_H2_HEADER_LEN,         35
        .equ ANNOUNCE_DESTINATION_HASH_SIZE, 16
        .equ ANNOUNCE_PUBLIC_KEY_SIZE,       64
        .equ ANNOUNCE_NAME_HASH_SIZE,        10
        .equ ANNOUNCE_RANDOM_HASH_SIZE,      10
        .equ ANNOUNCE_SIGNATURE_SIZE,        64
        .equ ANNOUNCE_PAYLOAD_FIXED_LEN,     149

        .equ ANNOUNCE_RAW_OFF_FLAGS,         0
        .equ ANNOUNCE_RAW_OFF_HOPS,          1
        .equ ANNOUNCE_RAW_OFF_DEST_HASH,     2
        .equ ANNOUNCE_RAW_OFF_CONTEXT,       18
        .equ ANNOUNCE_RAW_OFF_PUBLIC_KEY,    19
        .equ ANNOUNCE_RAW_OFF_NAME_HASH,     83
        .equ ANNOUNCE_RAW_OFF_RANDOM_HASH,   93
        .equ ANNOUNCE_RAW_OFF_SIGNATURE,     103
        .equ ANNOUNCE_RAW_OFF_APP_DATA,      167
        .equ ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID, 2
        .equ ANNOUNCE_H2_RAW_OFF_DEST_HASH,  18
        .equ ANNOUNCE_H2_RAW_OFF_CONTEXT,    34
        .equ ANNOUNCE_H2_RAW_OFF_PUBLIC_KEY, 35
        .equ ANNOUNCE_H2_RAW_OFF_NAME_HASH,  99
        .equ ANNOUNCE_H2_RAW_OFF_RANDOM_HASH, 109
        .equ ANNOUNCE_H2_RAW_OFF_SIGNATURE,  119
        .equ ANNOUNCE_H2_RAW_OFF_APP_DATA,   183

        .equ ANNOUNCE_SIGNED_OFF_DEST_HASH,  0
        .equ ANNOUNCE_SIGNED_OFF_PUBLIC_KEY, 16
        .equ ANNOUNCE_SIGNED_OFF_NAME_HASH,  80
        .equ ANNOUNCE_SIGNED_OFF_RANDOM_HASH, 90
        .equ ANNOUNCE_SIGNED_OFF_APP_DATA,   100

        /* For the 167-byte fixed announce prefix, app data is capped
         * by the configured Reticulum MDU. */
        .equ ANNOUNCE_RETICULUM_MDU,         RETICULUM_MDU
        .equ ANNOUNCE_BASE_RAW_LEN,          167
        .equ ANNOUNCE_H2_BASE_RAW_LEN,       183
        .equ ANNOUNCE_MAX_APP_DATA,          RETICULUM_MDU - ANNOUNCE_BASE_RAW_LEN
        .equ ANNOUNCE_KISS_TX_CAPACITY,      (RETICULUM_MDU * 2) + 3
        .equ ANNOUNCE_SIGNED_FIXED_LEN,      100
        .equ ANNOUNCE_SIGNED_DATA_MAX,       417

        /* announce_rx_t struct offsets (180 bytes total).
         *
         * App data remains a view into the bounded raw packet buffer:
         * ANNOUNCE_RX_OFF_APP_DATA_PTR points at the fixed app-data offset
         * for the parsed header shape and ANNOUNCE_RX_OFF_APP_DATA_LEN gives
         * the number of bytes to read.
         */
        .equ ANNOUNCE_RX_OFF_RAW_LEN,         0
        .equ ANNOUNCE_RX_OFF_PAYLOAD_LEN,     4
        .equ ANNOUNCE_RX_OFF_APP_DATA_LEN,    8
        .equ ANNOUNCE_RX_OFF_DEST_HASH,       12
        .equ ANNOUNCE_RX_OFF_PUBLIC_KEY,      28
        .equ ANNOUNCE_RX_OFF_NAME_HASH,       92
        .equ ANNOUNCE_RX_OFF_RANDOM_HASH,     102
        .equ ANNOUNCE_RX_OFF_SIGNATURE,       112
        .equ ANNOUNCE_RX_OFF_APP_DATA_PTR,    176
        .equ ANNOUNCE_RX_T_SIZE,              180
