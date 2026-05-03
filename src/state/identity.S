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
