# ADR-0010: USB-Serial/JTAG as the early-bring-up serial backend

- **Status:** Accepted (refines [ADR-0004](0004-diagnostics.md))
- **Date:** 2026-05-02

## Context

[ADR-0004](0004-diagnostics.md) selected UART0 over an external USB-serial dongle as the
permanent diagnostic transport, on the basis that "the USB Serial/JTAG peripheral … requires
a USB stack in asm, which is non-trivial." During hardware bring-up of the Adafruit ESP32-C6
Feather (2026-05-02) we discovered this is not actually the case: the C6's mask-ROM already
performs USB device enumeration as a CDC-ACM endpoint, and our firmware sees the peripheral
as a memory-mapped FIFO with a 1-byte-wide TX/RX register pair plus three control flags
(`SERIAL_IN_EP_DATA_FREE`, `SERIAL_OUT_EP_DATA_AVAIL`, `WR_DONE`). The "USB stack in asm"
work the original ADR feared is entirely in the mask ROM.

The practical bring-up consequence: the Adafruit Feather has a single USB-C jack wired to
the C6's USB-Serial/JTAG peripheral. There is no on-board USB-serial dongle for UART0; the
GPIO16/17 pins exit the board on a header for an external dongle. For first-light bring-up
"just plug in USB-C and see boot output" is enormously cheaper than "wire up a CP2102 to
GPIO16/17 first." Once a wired dongle is on bench, the spec'd UART0 path remains the
production transport.

## Decision

The C6 build (`TARGET=c6`) drives the existing `uart_*` API surface against the USB-Serial/
JTAG peripheral at register base `0x6000_F000`. The same five primitives — `uart_init`,
`uart_tx_byte`, `uart_rx_byte`, `uart_rx_available`, `uart_tx_bytes` — emit and consume bytes
through the USJ FIFO instead of a NS16550A or 8250-style UART. The structured-log API and
line format (ADR-0004) are unchanged: callers see the same `uart_*` contract and the host
sees the same `<ts_ms>\t<module>\t<event>...\r\n` framing on the CDC-ACM serial endpoint.

UART0 over GPIO16/17 remains the spec'd "permanent" diagnostic transport per ADR-0004. It
lands under `TARGET_C6` once an external USB-serial dongle is on bench; the corresponding
`uart_*` paths will be added behind a build-time flag (`UART0_BACKEND=gpio16_17` vs
`USB_SERIAL_JTAG`, default the latter on the Feather).

## Consequences

### Positive

- First-light bring-up needs no extra hardware beyond the USB-C cable already used for
  flashing. The `make flash && make monitor` loop closes in seconds.
- The structured log goes to the same enumerated `/dev/cu.usbmodemNNNN` device that
  esptool talks to, so a single serial port serves both flashing and observation. No
  port-juggling, no dongle-driver installs.
- The mask-ROM is already running the USB CDC-ACM stack at boot; we inherit a working
  enumeration without reset-to-bootloader cycles.
- The peripheral has hardware FIFOs (~64 bytes IN, ~64 bytes OUT). Even with the current
  flush-per-byte TX path, the host receives one batched USB-IN transfer per ~1 ms, which
  is enough for milestone-1's log volume.

### Negative

- TX is not interrupt-driven (the per-byte `WR_DONE` flush blocks until the host's USB
  stack clears the IN endpoint). The polled path caps throughput at ~1 KiB/s. Acceptable
  for milestone-1 logging; replaced with chunked or auto-flush when the crypto KAT bridge
  starts emitting larger lines.
- The peripheral is `usb_serial_jtag` not a true UART, so the `baud` parameter the host
  picks is informational. Most CDC-ACM hosts default to 115200; `make monitor` matches.
- ADR-0004's "external dongle" assumption is no longer load-bearing for first-light. We
  do not rewrite ADR-0004 — its core decisions (structured logging, the `log_*` API, the
  line format) are unchanged — but its **Context** §3 should not be cited as a reason
  against USB-Serial/JTAG in future ADRs. Use this ADR as the reference instead.
- A second `uart_*` backend implementation (the GPIO16/17 path) lands later. Both must
  satisfy the same byte-stream contract, so the `uart_*` test suite covers both via the
  `TARGET=` build flag.

## Alternatives considered

- **Continue requiring an external USB-serial dongle for first-light.** Rejected: the
  bench-equipment cost was real and the "USB stack in asm" assumption that justified it
  was wrong.
- **Drive both UART0 and USJ in parallel from `uart_tx_byte`.** Rejected for milestone 1:
  doubles the polling cost per byte and forces both backends to be live before either
  is needed. May revisit if a "log goes to both for redundancy" pattern proves useful.
- **Keep UART0 the only `uart_*` backend and add a separate `usj_*` family.** Rejected:
  the `_main` boot loop and `log_*` primitives are already tied to `uart_*`. Threading a
  second API through them costs more than the per-target `.ifdef` switch we use today.
