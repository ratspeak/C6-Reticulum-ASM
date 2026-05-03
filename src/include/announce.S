/* Reticulum HEADER_1 announce constants for milestone 3.
 *
 * Non-ratchet announce packet:
 *   flags[1] || hops[1] || destination_hash[16] || context[1] ||
 *   public_key[64] || name_hash[10] || random_hash[10] ||
 *   signature[64] || app_data
 */

        .include "config.S"

        .equ ANNOUNCE_HEADER_FLAGS,          0x01
        .equ ANNOUNCE_HEADER_HOPS,           0x00
        .equ ANNOUNCE_CONTEXT_NONE,          0x00

        .equ ANNOUNCE_HEADER_LEN,            19
        .equ ANNOUNCE_RANDOM_HASH_SIZE,      10
        .equ ANNOUNCE_SIGNATURE_SIZE,        64

        .equ ANNOUNCE_RAW_OFF_FLAGS,         0
        .equ ANNOUNCE_RAW_OFF_HOPS,          1
        .equ ANNOUNCE_RAW_OFF_DEST_HASH,     2
        .equ ANNOUNCE_RAW_OFF_CONTEXT,       18
        .equ ANNOUNCE_RAW_OFF_PUBLIC_KEY,    19
        .equ ANNOUNCE_RAW_OFF_NAME_HASH,     83
        .equ ANNOUNCE_RAW_OFF_RANDOM_HASH,   93
        .equ ANNOUNCE_RAW_OFF_SIGNATURE,     103
        .equ ANNOUNCE_RAW_OFF_APP_DATA,      167

        .equ ANNOUNCE_SIGNED_OFF_DEST_HASH,  0
        .equ ANNOUNCE_SIGNED_OFF_PUBLIC_KEY, 16
        .equ ANNOUNCE_SIGNED_OFF_NAME_HASH,  80
        .equ ANNOUNCE_SIGNED_OFF_RANDOM_HASH, 90
        .equ ANNOUNCE_SIGNED_OFF_APP_DATA,   100

        /* For the 167-byte fixed announce prefix, app data is capped
         * by the configured Reticulum MDU. */
        .equ ANNOUNCE_RETICULUM_MDU,         RETICULUM_MDU
        .equ ANNOUNCE_BASE_RAW_LEN,          167
        .equ ANNOUNCE_MAX_APP_DATA,          RETICULUM_MDU - ANNOUNCE_BASE_RAW_LEN
        .equ ANNOUNCE_SIGNED_FIXED_LEN,      100
        .equ ANNOUNCE_SIGNED_DATA_MAX,       417
