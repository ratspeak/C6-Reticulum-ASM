# Mutable state for the KISS codec (per ADR-0002 — single .bss home for
# the kiss module). Symbols are global so the kiss_* functions can refer
# to them by name across translation units; per check_registry's typed
# rule, data globals (no .type @function) are not in the function
# registry.

        .include "config.S"

        .section .bss.kiss_state, "aw", @nobits
        .global kiss_in_frame
        .global kiss_escaped
        .global kiss_saw_type
        .global kiss_buf_len
kiss_in_frame:  .skip 1
kiss_escaped:   .skip 1
kiss_saw_type:  .skip 1
                .skip 1                 /* alignment pad                 */
kiss_buf_len:   .skip 4

        .section .bss.kiss_buf, "aw", @nobits
        .global kiss_buf
kiss_buf:       .skip KISS_MAX_FRAME
