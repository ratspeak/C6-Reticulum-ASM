# ============================================================================
# @function:    _main
# @module:      boot
# @inputs:      (none; entered from _reset)
# @outputs:     (does not return; emits the boot banner over UART0)
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
 *   5. emit a hard-coded banner so the harness can confirm the boot
 *      reached steady state.
 *   6. wfi loop forever.
 *
 * The banner is the literal "00000000\tboot\tready\r\n" — same shape as
 * the eventual log_event output so the parser regression-tests the same
 * format from day one. Step 5 will be replaced with `call log_init` +
 * `call log_event` once the log primitives ship.
 */

        .section .rodata.boot_banner, "a"
.Lboot_banner:
        .ascii "00000000\tboot\tready\r\n"
.Lboot_banner_end:
        .equ   .Lboot_banner_len, .Lboot_banner_end - .Lboot_banner

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

        la      a0, .Lboot_banner
        li      a1, .Lboot_banner_len
        call    uart_tx_bytes

1:      wfi
        j       1b

        .size   _main, . - _main
