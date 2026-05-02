# ADR-0004: Structured UART logging as the permanent diagnostic channel

- **Status:** Accepted
- **Date:** 2026-05-01

## Context

A multi-year asm project will spend the majority of its lifetime debugging. The diagnostic
channel must be in place before the first non-trivial asm function is written, or it will
never be retrofitted consistently — and the cost of debugging crypto, state machines, and
hardware drivers without good observability is days per bug.

The candidate diagnostic mechanisms on the ESP32-C6:

1. **LED toggling.** Effectively zero code, single bit of information per event. Useful as
   a "we got here" signal in the very first bring-up, but useless once we need to debug
   anything more complex than "did the boot run."
2. **JTAG/SWD with on-target debugging.** The most powerful option, requires a hardware
   debugger and a working OpenOCD configuration. Excellent for single-stepping but a poor
   medium for "show me what happened over the last 100 ms across these five functions."
3. **USB Serial/JTAG peripheral.** The C6 has a built-in USB peripheral that can present
   as a CDC serial device. Slick (no external dongle) but requires a USB stack in asm,
   which is non-trivial.
4. **UART over an external USB-serial dongle.** A few lines of code to bring up, completely
   asynchronous to whatever we are debugging, parseable by host tools. The standard choice
   for embedded development.

We also have to decide on the *format* of log output. Free-form text is what most projects
default to and is what most projects regret. A structured, machine-parseable format is more
work to emit but enables automated harness-side analysis (tests can assert "the log shows
event X with field Y" rather than grepping).

## Decision

The permanent diagnostic channel is structured logging emitted over UART0 to an external
USB-serial dongle. The decision has three parts:

1. **Transport: UART0 at 115200 8N1**, pins per the Adafruit Feather pinout (GPIO 16/17 on
   the C6). External USB-serial dongle (CP2102, CH340, FT232, etc.) on the host side.

2. **API: a small set of typed log primitives**, callable from any asm function:
   - `log_str(a0=ptr, a1=len)` — emit a string literal with no formatting.
   - `log_hex(a0=value, a1=width)` — emit a hexadecimal integer.
   - `log_u32(a0=value)` — emit an unsigned decimal integer.
   - `log_bytes(a0=ptr, a1=len)` — emit a byte buffer as space-separated hex.
   - `log_event(a0=tag_ptr, a1=tag_len)` — emit a structured event tag and CRLF-terminate.
   No `printf`-equivalent. No format strings. No varargs.

3. **Format: line-oriented, tab-separated, CRLF-terminated**, with a fixed prefix:
   ```
   <ts_ms>\t<module>\t<event>\t<key>=<value>[\t<key>=<value>...]\r\n
   ```
   - `<ts_ms>` is milliseconds since boot, monotonic.
   - `<module>` is the originating module name (e.g., `kiss`, `sha256`, `tx`).
   - `<event>` is a fixed string identifying the event type.
   - `<key>=<value>` pairs carry hex or decimal data. Whitespace is forbidden in values.

   Example: `00012345\tkiss\trx_frame\tlen=64\tdest=a1b2c3d4\r\n`

   The harness parses this format reliably; humans can read it as well.

## Consequences

### Positive

- Available from day one with minimal code (a UART driver and ~5 log primitives).
- No external hardware beyond a $3 USB-serial dongle.
- Structured format means the test harness can make assertions against log content
  programmatically. Tests like "after sending an announce, the log emits one `tx_frame` event
  with `dest=<expected_hash>`" become straightforward.
- The log itself is permanent infrastructure — every milestone uses it, no rewrite needed.
- Asynchronous to execution: logging does not block the main path (the UART TX is interrupt-
  driven with a ring buffer), so it does not perturb timing-sensitive code.

### Negative

- Logging in constant-time crypto is forbidden during the secret-handling section, since log
  emissions can leak timing. Crypto functions log only at entry and exit, never in the middle.
  The `@ct` discipline enforces this.
- The log primitives themselves must not allocate, must not call indirectly (so they do not
  blow stack budgets in callees), and must be safe to invoke from any context including IRQ
  handlers. This is a constraint the milestone-1 implementation must meet.
- We pay UART pins (two GPIOs) that cannot be used for anything else.

### Neutral

- The USB Serial/JTAG peripheral is preserved as an option for later (post-milestone-8)
  if we want a no-dongle workflow, but the primary diagnostic path is UART. A switch later
  would be a new ADR; existing code continues to work either way because the API is `log_*`,
  not "write to USB."
- LED is still wired up for the most basic "did boot complete" signal but is not the
  diagnostic channel. It is a power-on health indicator only.

## Alternatives considered

**Free-form text logging (printf-style).** Reject. Format strings in asm are awkward, varargs
are worse, and the harness cannot reliably parse free text as the format evolves.

**Binary protocol over UART.** Reject. The marginal efficiency win does not justify the
loss of human readability during interactive debugging. Structured text is the right tradeoff.

**JTAG/SWD as the primary channel.** Reject. Excellent for single-stepping but poor for
trace logging. We will configure JTAG for occasional deep debugging but it is not the
permanent channel.

## References

- ADR-0006 — formal verification, including constant-time policy that constrains logging
  in crypto functions.
- Milestone 1 spec — implements the UART driver and log API.
- Adafruit ESP32-C6 Feather pinout (vendored at `references/adafruit-esp32c6-feather-pinout.pdf`).
