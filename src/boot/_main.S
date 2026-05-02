# ============================================================================
# @function:    _main
# @module:      boot
# @inputs:      (none; entered from _reset)
# @outputs:     (does not return; emits the boot.ready log event over UART0)
# @clobbers:    a0, a1, t0..t6, ra
# @preserves:   sp, gp, s0..s11
# @stack:       16
# @cycles:      unbounded
# @ct:          not-required
# @spec:        milestone-1 §boot
# @verify:      kat-only; top-level event loop, integration via tests/boot/test__main.py
# @tests:       tests/boot/test__main.py
# @adrs:        0001, 0004, 0008
# @status:      verified
# ============================================================================

/* Bring-up sequence:
 *   1. _init_bss  — zero .bss
 *   2. _init_data — populate .data from its load image (no-op on qemu-virt)
 *   3. clock_init — bring CPU clock to spec (no-op on qemu-virt)
 *   4. uart_init  — set up UART0 (no-op on qemu-virt)
 *   5. log_init   — set up log subsystem (placeholder until clock_get_freq)
 *   6. log_event(boot.ready) — first structured log line on UART0
 *   7. wfi loop forever (the polling main-loop replacement lands when
 *      kiss + packet are wired and there is real work to do).
 */

        .section .rodata.boot_event_tag, "a"
.Lboot_ready_tag:
        .ascii "boot\tready"
.Lboot_ready_tag_end:
        .equ   .Lboot_ready_tag_len, .Lboot_ready_tag_end - .Lboot_ready_tag

        .section .text._main, "ax", @progbits
        .global _main
        .type   _main, @function
_main:
        addi    sp, sp, -16
        sw      ra, 12(sp)

        call    _init_bss
        call    _init_data
        call    clock_init
        call    uart_init
        call    log_init

        la      a0, .Lboot_ready_tag
        li      a1, .Lboot_ready_tag_len
        call    log_event

1:      wfi
        j       1b

        .size   _main, . - _main
