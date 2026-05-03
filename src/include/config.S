/* Compile-time configuration constants (per ADR-0002).
 *
 * Single source of truth for capacities (buffer sizes, table caps, stack
 * size). Changing any of these is a relink, not a runtime configuration.
 *
 * Per-target overrides go in `config_<target>.S` if/when needed; today
 * the qemu-virt and C6 targets share the same defaults.
 */

/* Stack region (.stack) reserved at the top of SRAM, sized at link time.
 * The static-analyzer in tools/ will assert worst-case stack depth fits. */
        .equ STACK_SIZE,            0x4000      /* 16 KiB */

/* UART0 ring buffers (per milestone-1 §uart). 1024 bytes each accommodates
 * one full Reticulum MTU + log overhead. */
        .equ UART0_TX_RING_SIZE,    1024
        .equ UART0_RX_RING_SIZE,    1024

/* Reticulum maximum data unit used by packet/announce buffer sizing. */
        .equ RETICULUM_MDU,         484

/* KISS decoder maximum frame size (per milestone-1 §kiss). Reticulum's
 * MDU is 484 bytes; we leave headroom for KISS escapes (worst case 2x). */
        .equ KISS_MAX_FRAME,        1024

/* Log line buffer for `log_event`. A single line never exceeds this; the
 * parser truncates if it does (defensive only — no callers should hit it). */
        .equ LOG_LINE_MAX,          256
