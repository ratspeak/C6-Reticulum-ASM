# Reticulum packet header layout + packet_t struct offsets.
#
# Authoritative spec: upstream/Reticulum/RNS/Packet.py.unpack() and
# RNS.Reticulum.TRUNCATED_HASHLENGTH (128 bits → 16 bytes).
#
# The packet_t struct is caller-provided (per ADR-0002, no allocation);
# parsers populate it from a raw buffer. Each accessor reads from this
# struct and returns pointers into the original buffer — the struct is
# pure metadata, the bytes live where the caller put them.

# --- packet_t struct offsets (24 bytes total, 4-byte aligned) ----------
        .equ PKT_OFF_HEADER_BYTE,   0       /* uint8                     */
        .equ PKT_OFF_HOPS,          1       /* uint8                     */
        .equ PKT_OFF_HEADER_TYPE,   2       /* uint8: 0 (H1) or 1 (H2)   */
        .equ PKT_OFF_PACKET_TYPE,   3       /* uint8: bits 0..1 of flags */
        .equ PKT_OFF_DEST_HASH_OFF, 4       /* uint16 offset into raw    */
        .equ PKT_OFF_PAYLOAD_OFF,   8       /* uint16 (4-byte aligned)   */
        .equ PKT_OFF_PAYLOAD_LEN,  12       /* uint16                    */
        .equ PKT_OFF_RAW_LEN,      16       /* uint16                    */
        .equ PKT_OFF_RAW_PTR,      20       /* void* (4 bytes)           */
        .equ PKT_T_SIZE,           24

# --- header constants (mirrors upstream Packet.py) ---------------------
        .equ HASH_LEN,              16      /* TRUNCATED_HASHLENGTH/8    */
        .equ HEADER_MINSIZE,        19      /* 2 + 1 + 16 (HEADER_1)     */
        .equ HEADER_H2_SIZE,        35      /* 2 + 1 + 16*2 (HEADER_2)   */

        .equ FLAG_IFAC,             0x80    /* bit 7                     */
        .equ FLAG_HEADER_TYPE,      0x40    /* bit 6                     */
        .equ FLAG_CONTEXT,          0x20    /* bit 5                     */
        .equ FLAG_TRANSPORT,        0x10    /* bit 4                     */
        .equ MASK_DEST_TYPE,        0x0C    /* bits 2..3                 */
        .equ MASK_PACKET_TYPE,      0x03    /* bits 0..1                 */

        .equ HEADER_1,              0
        .equ HEADER_2,              1

        .equ PKT_DATA,              0x00
        .equ PKT_ANNOUNCE,          0x01
        .equ PKT_LINKREQUEST,       0x02
        .equ PKT_PROOF,             0x03

# --- parse-status return codes -----------------------------------------
        .equ PKT_OK,                0
        .equ PKT_ERR_TRUNCATED,    -1       /* buf_len < expected header  */
