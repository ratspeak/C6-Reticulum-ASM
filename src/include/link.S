/* Reticulum link request constants for milestone 6.
 *
 * Current upstream Reticulum link request payload:
 *   x25519_public[32] || ed25519_link_signing_public[32] ||
 *   signalling[3]
 *
 * The three signalling bytes encode the link MTU and cipher mode according
 * to RNS.Link.signalling_bytes(). Milestone 6 supports the current default
 * AES-256-CBC mode with MTU 500 only.
 */

        .include "config.S"
        .include "x25519.S"
        .include "ed25519.S"

        .equ LINK_OK,                         0
        .equ LINK_ERR_INVAL,                 -1
        .equ LINK_ERR_OVERFLOW,              -2

        .equ LINK_HEADER_LEN,                 19
        .equ LINK_DESTINATION_HASH_SIZE,      16
        .equ LINK_X25519_PUB_SIZE,            X25519_WIRE_BYTES
        .equ LINK_ED25519_PUB_SIZE,           ED25519_PUB_BYTES
        .equ LINK_SIGNAL_SIZE,                3

        .equ LINK_MODE_AES256_CBC,            1
        .equ LINK_MODE_MASK,                  0xE0
        .equ LINK_MTU_BYTEMASK_HIGH,          0x1F
        .equ LINK_DEFAULT_MTU,                500
        .equ LINK_SIGNAL_BYTE0,               0x20
        .equ LINK_SIGNAL_BYTE1,               0x01
        .equ LINK_SIGNAL_BYTE2,               0xF4

        .equ LINK_REQUEST_HEADER_FLAGS,       0x02
        .equ LINK_REQUEST_HEADER_HOPS,        0x00
        .equ LINK_REQUEST_CONTEXT_NONE,       0x00

        .equ LINK_REQUEST_RAW_OFF_FLAGS,      0
        .equ LINK_REQUEST_RAW_OFF_HOPS,       1
        .equ LINK_REQUEST_RAW_OFF_DEST_HASH,  2
        .equ LINK_REQUEST_RAW_OFF_CONTEXT,    18
        .equ LINK_REQUEST_RAW_OFF_X25519_PUB, 19
        .equ LINK_REQUEST_RAW_OFF_ED25519_PUB, 51
        .equ LINK_REQUEST_RAW_OFF_SIGNAL0,    83
        .equ LINK_REQUEST_RAW_OFF_SIGNAL1,    84
        .equ LINK_REQUEST_RAW_OFF_SIGNAL2,    85
        .equ LINK_REQUEST_PAYLOAD_LEN,        67
        .equ LINK_REQUEST_RAW_LEN,            86
        .equ LINK_REQUEST_RETICULUM_MDU,      RETICULUM_MDU

        /* link_request_t struct offsets (92 bytes total, 4-byte aligned). */
        .equ LINK_REQUEST_OFF_RAW_LEN,        0
        .equ LINK_REQUEST_OFF_MTU,            4
        .equ LINK_REQUEST_OFF_MODE,           8
        .equ LINK_REQUEST_OFF_DEST_HASH,      12
        .equ LINK_REQUEST_OFF_X25519_PUB,     28
        .equ LINK_REQUEST_OFF_ED25519_PUB,    60
        .equ LINK_REQUEST_T_SIZE,             92

        .equ LINK_SHARED_SECRET_SIZE,         32
        .equ LINK_PRK_SIZE,                   32
        .equ LINK_KEY_MATERIAL_SIZE,          64
