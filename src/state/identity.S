/* Static milestone-3 identity state (ADR-0002).
 *
 * `_main` uses this as the current development identity for the announce TX
 * dispatcher path. Persistence moves this backing store to flash in
 * milestone 4.
 */

        .include "identity.S"

        .section .bss.identity_state, "aw", @nobits
        .global identity_current
        .type   identity_current, @object
        .balign 16
identity_current:
        .zero   IDENTITY_T_SIZE
        .size   identity_current, IDENTITY_T_SIZE

        .global identity_record_buf
        .type   identity_record_buf, @object
        .balign 16
identity_record_buf:
        .zero   IDENTITY_RECORD_SIZE
        .size   identity_record_buf, IDENTITY_RECORD_SIZE

        .global identity_verify_buf
        .type   identity_verify_buf, @object
        .balign 16
identity_verify_buf:
        .zero   IDENTITY_RECORD_SIZE
        .size   identity_verify_buf, IDENTITY_RECORD_SIZE

        .global identity_hash_buf
        .type   identity_hash_buf, @object
        .balign 4
identity_hash_buf:
        .zero   IDENTITY_HASH_SIZE
        .size   identity_hash_buf, IDENTITY_HASH_SIZE
