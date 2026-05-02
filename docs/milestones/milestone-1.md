# Milestone 1: Foundation stack + verifier infrastructure

- **Status:** Active
- **Started:** 2026-05-01
- **Estimate:** 8–12 weeks

## Goal

Lay every permanent foundation the rest of the project depends on. By the end of this
milestone, the device boots from cold, runs to a known state, drives UART0, emits structured
logs, frames and parses KISS, parses Reticulum packet headers received from a Python `rnsd`
peer, and reports findings via the structured log. Every line of asm written is permanent;
the test harness and formal verifier infrastructure are in place; FUNCTIONS.md is the
authoritative tracker.

The outwardly visible demonstration ("the C6 receives Reticulum announces from `rnsd` over a
serial cable and logs each one") is a side effect of building the foundations. The foundations
themselves are the milestone.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Toolchain configuration | [§Toolchain](#toolchain) | Forever |
| Linker script (`toolchain/c6.ld`) | [§Toolchain](#toolchain) | Forever |
| Boot sequence | [§boot](#boot) | Forever |
| Clock/PLL configuration | [§clock](#clock) | Forever |
| UART0 driver | [§uart](#uart) | Forever |
| Structured logging | [§log](#log) | Forever |
| KISS codec | [§kiss](#kiss) | Forever |
| Reticulum packet parser | [§packet](#packet) | Forever |
| Test harness skeleton | [§harness](#harness) | Forever |
| Verifier infrastructure | [§verifier](#verifier) | Forever |
| Spec-block parser (`tools/parse_spec.py`) | [§tools](#tools) | Forever |
| `./verify` dispatch script | [§tools](#tools) | Forever |

## Definition of done

Every condition is objectively verifiable. The milestone is not `Complete` until every box
is checked.

- [ ] Repository builds from a clean clone with one `make` invocation, producing a flashable
      `.bin`.
- [ ] `./verify --all` returns green for every function listed under "verified" in
      FUNCTIONS.md for this milestone.
- [ ] Every function in this milestone has status `verified` in FUNCTIONS.md.
- [ ] Every `.S` file in `src/` has a complete and valid spec block (verified by
      `tools/parse_spec.py`).
- [ ] The harness can drive `./verify <function>` for every function and produces structured
      output in both human and JSON modes.
- [ ] The hardware demo: a Python `rnsd` running on the host, configured with a `KISSInterface`
      pointed at the USB-serial line to the C6, emits announces; the C6's log shows one
      `packet_rx` event per received announce, with the correct destination hash and packet
      type fields decoded.
- [ ] The same demo runs in `emu` mode (qemu-system-riscv32) with crafted KISS-framed
      announce inputs, producing identical log output.
- [ ] CI configuration in `.github/workflows/` (or local equivalent) runs `./verify --all` on
      every commit (this repo is local-only per ADR; CI may be `make ci` invoked from a
      pre-push hook initially).
- [ ] All ADRs 0001–0007 are referenced by at least one function in this milestone, proving
      the architecture is in active use.

## Hardware setup

Required hardware:

- 1× Adafruit ESP32-C6 Feather (4 MB flash, 320 KB SRAM).
- 1× USB-C cable (board to host).
- 1× USB-serial dongle (CP2102, CH340, or FT232) for diagnostic UART. Some workflows can
  reuse the board's USB Serial/JTAG for diagnostics, but per ADR-0004 the primary path is
  external UART.
- 3× jumper wires (UART TX, UART RX, GND between dongle and Feather).
- (Optional) JTAG/SWD probe for advanced debugging — not required for this milestone.

Pinout, per Adafruit ESP32-C6 Feather schematic (vendored once acquired):

| Signal | C6 GPIO | Feather pin | Connects to |
|--------|---------|-------------|-------------|
| UART0 TX | GPIO 16 | (silkscreen `TX`) | Dongle RX |
| UART0 RX | GPIO 17 | (silkscreen `RX`) | Dongle TX |
| GND | — | GND | Dongle GND |
| LED | GPIO 15 | (on-board NeoPixel power: GPIO 20; data: GPIO 19) | — |

The on-board NeoPixel is more complex than a plain LED (WS2812 protocol). For milestone 1's
power-on indicator, we may either drive the NeoPixel (deferring to a `neopixel` module) or
use a simple GPIO with an external LED. Decision deferred to the boot section.

## Toolchain

Specified in detail in [toolchain/README.md](../../toolchain/README.md). Summary:

- **Assembler/linker:** `riscv32-esp-elf-as`, `riscv32-esp-elf-ld` (Espressif fork).
  Used as assembler and linker only; no C compiler is invoked on our sources.
- **Flasher:** `esptool.py` (Espressif's official Python flasher).
- **Emulator:** `qemu-system-riscv32` with C6-compatible machine model. Sail-derived where
  available; otherwise vanilla qemu with a custom device tree.
- **Harness:** Python 3.11+, `pyserial`, `pytest`, `rns` (the upstream Python Reticulum).
- **Verifiers:** see [proofs/README.md](../../proofs/README.md). Initial install: `angr`,
  `python-tla` for TLA+ tooling. SAW + Cryptol install deferred to milestone 2 when crypto
  arrives. Per [ADR-0008](../adr/0008-naming-toolchain-format.md), the directory was renamed
  from `verify/`.

Versions are pinned in `toolchain/versions.lock`. Bumping a version requires re-running
`./verify --all` and committing only if green.

### Linker script (`toolchain/c6.ld`)

The linker script defines the static memory map per ADR-0002. Skeleton:

- `.text` in flash, starting after the Espressif boot ROM image header.
- `.rodata` in flash, after `.text`.
- `.data` in flash, copied to SRAM at boot.
- `.bss` in SRAM, zeroed at boot.
- `.stack` in SRAM, reserved at the top, size set in `src/include/config.S`.
- The Espressif image header is prepended; format documented in
  `docs/hardware/image-header.md` (to be written during this milestone).

Section addresses are derived from the C6 Technical Reference Manual. Every byte of SRAM is
accounted for: the build fails if `(text + rodata + data) > flash_size` or `(data + bss +
stack) > sram_size - reserved`.

## boot

Module: `boot`. Functions are listed in [FUNCTIONS.md](../../FUNCTIONS.md#module-boot).

### `_reset`

Reset vector. First instructions executed on cold start.

```
;; @function:    _reset
;; @module:      boot
;; @inputs:      (none; entered from reset)
;; @outputs:     (transfers to _main)
;; @clobbers:    all (initial state is undefined)
;; @preserves:   (none)
;; @stack:       0 (stack not yet valid until set up here)
;; @cycles:      bounded (~50)
;; @ct:          not-required
;; @spec:        ESP32-C6 TRM §3 (Reset and Boot), this milestone §boot
;; @verify:      kat-only (entry-point semantics; no functional contract)
;; @tests:       tests/boot/test__reset.py
;; @adrs:        0001, 0002
;; @status:      planned
```

Responsibilities:
1. Set `sp` to top of stack region.
2. Set `gp` to the linker-defined global pointer.
3. Jump to `_init_bss`.

### `_init_bss`

Zero the BSS region.

### `_init_data`

Copy the `.data` section from flash to its SRAM destination.

### `_main`

The top-level entry point after runtime init. Responsibilities:
1. Call `clock_init` (bring chip to 160 MHz).
2. Call `uart_init`.
3. Call `log_init`.
4. Emit `boot\tready\t` event.
5. Enter the main event loop: poll `kiss_decode_byte` against bytes from `uart_rx_byte`,
   dispatch completed frames to `packet_parse_header`, log each parse result.

The main loop is intentionally simple in this milestone. Future milestones will replace it
with a proper scheduler.

## clock

Module: `clock`. Brings the chip from default (40 MHz crystal, possibly running at lower
frequency from boot ROM) to a known 160 MHz operating state.

The C6 PLL configuration is documented in the ESP32-C6 TRM Chapter 6 (Clock Tree). The
sequence is:

1. Switch CPU clock source to crystal (XTAL, 40 MHz) temporarily.
2. Configure PLL multipliers.
3. Wait for PLL lock.
4. Switch CPU clock source to PLL output.
5. Set bus clock dividers.

Detailed register sequences are deferred to the implementation; the spec block in each
function will reference the TRM section.

`clock_delay_us` is a busy-wait by cycle counting. Used during peripheral initialization and
LoRa register access (milestone 8). Constant-time is not required since delay is the entire
purpose.

## uart

Module: `uart`. UART0 driver. Interrupt-driven RX and TX with ring buffers, both sized in
`src/include/config.S`.

Design:
- TX: `uart_tx_byte` enqueues into the TX ring buffer; the TX-empty IRQ pops bytes into the
  UART data register. Blocks if the ring is full.
- RX: the RX IRQ pushes received bytes into the RX ring buffer. `uart_rx_byte` pops from it;
  `uart_rx_available` reports the count without removing.
- `uart_isr` dispatches on the UART interrupt cause register and updates the appropriate
  ring buffer. Per ADR-0004, the ISR is small and bounded: no logging, no allocation.

Ring buffer state (RX and TX) lives in `src/state/uart.S`. Size constants in
`src/include/config.S`:
- `UART0_TX_RING_SIZE`: 1024 bytes (enough for one full Reticulum MTU + log overhead).
- `UART0_RX_RING_SIZE`: 1024 bytes.

## log

Module: `log`. The structured logging API per ADR-0004. Five primitives plus `log_init`,
each implemented as small leaf functions.

`log_event` is the canonical event emitter. Calling pattern:

```
;; emit "00012345\tkiss\trx_frame\tlen=64\tdest=a1b2c3d4\r\n"
la   a0, .Ltag_kiss_rx_frame
li   a1, .Ltag_kiss_rx_frame_len
call log_event
li   a0, 64
call log_u32     ; emits "len=" prefix and value
...
```

Field separators (`\t`) and line terminator (`\r\n`) are emitted by the primitives, not by
the caller, so format consistency cannot drift. Exact API contracts are specified in each
function's spec block.

## kiss

Module: `kiss`. KISS framing per the original KISS specification (Karn, 1986; Reticulum's
KISS use is identical to the original).

`kiss_decode_byte` is a state-machine that consumes one byte per call and outputs a complete
frame when the closing FEND arrives. State lives in `src/state/kiss.S`. The function returns
status: `0` = no frame yet, `1` = frame complete, `<0` = framing error.

`kiss_encode_frame` takes a payload buffer and produces an escaped output buffer. Caller
provides both buffers; per ADR-0002, no allocation.

`kiss_decode_reset` clears the decoder state on framing error or harness command.

Verification (per ADR-0006, "pure data transformation" category):
- Refinement proof against the KISS spec: for any input byte sequence, the decoded frames
  match the spec's expected outputs. SAW + Cryptol model.
- Symbolic execution on bounded inputs (up to MTU).

## packet

Module: `packet`. Reticulum wire format header parser. Reference: `upstream/Reticulum/RNS/Packet.py`
and the Reticulum manual §6 (Packet Format).

The Reticulum packet header layout:

| Bytes | Field | Notes |
|-------|-------|-------|
| 0 | Header byte | IFAC flag, header type, propagation type, destination type, packet type |
| 1 | Hops | 8-bit hop counter |
| 2..17 (or 2..33) | Destination(s) | 16-byte hash; or two for transport-routed |
| variable | Context | Optional |
| variable | Data | Payload |

`packet_parse_header` reads a buffer and populates a fixed-layout `packet_t` struct in caller-
provided memory. Returns parse status. Does not allocate. Does not validate signatures (that
is milestone 5+).

Field accessors (`packet_get_dest_hash`, `packet_get_payload`) read from the parsed struct
and return pointers into the original buffer.

`packet_serialize_header` is the inverse. Skeleton in this milestone (some fields stubbed);
real fields filled in by milestone 3 (announce TX) and beyond. The struct layout is fixed
now and survives forever.

Verification: refinement proof against the Python reference (parse a buffer in both, compare
struct outputs). Symbolic execution for malformed inputs (must never read past buffer end).

## harness

Lives in `tests/`. See [tests/README.md](../../tests/README.md) for layout.

This milestone implements the harness skeleton:

1. `tests/harness/target.py` — abstract `Target` class with three concrete subclasses:
   - `EmuTarget` — drives qemu-system-riscv32 with a flashed binary.
   - `HwTarget` — drives the physical Feather over USB-serial; flashes via `esptool.py`.
   - `OracleTarget` — drives a subprocess `python3 -m RNS.Utilities.rnsd` with a configured
     KISSInterface; used for differential testing in cryptography and packet handling.
2. `tests/harness/log_parser.py` — parses the ADR-0004 log format into structured events.
3. `tests/harness/verify.py` — the `./verify` dispatcher (a wrapper script in repo root
   delegates here). Reads `@verify` and `@tests` from the function's spec block, runs
   tests on every available target, runs the verifier, prints structured pass/fail.
4. Test files for every milestone-1 function under `tests/<module>/test_<function>.py`.

## verifier

Lives in `proofs/` (renamed from `verify/` per [ADR-0008](../adr/0008-naming-toolchain-format.md)).
See [proofs/README.md](../../proofs/README.md) for the per-category tooling.

This milestone implements:

1. `proofs/README.md` — the policy and tool index.
2. `proofs/kiss/kiss_decode_byte.saw` — SAW spec for the KISS decoder. The first formally
   verified function in the project.
3. `proofs/packet/packet_parse_header.saw` — SAW spec for the packet header parser.
4. `proofs/boot/contracts.md` — register-state contracts for the boot functions (since they
   have no functional spec, contracts are the verifier).
5. The `./verify` dispatcher knows how to invoke SAW for `.saw` files; future milestones add
   TLA+ and constant-time support.

## tools

Lives in `tools/`.

- `tools/parse_spec.py` — parses the spec block at the top of each `.S` file. Validates
  every required field is present and well-formed. Cross-checks `@adrs` against the ADR
  index, `@tests` and `@verify` against the filesystem, and `@status: verified` against the
  current `./verify` result.
- `tools/check_registry.py` — cross-checks `FUNCTIONS.md` against `src/`: every registered
  function has a source file; every source file has a registry entry; every dependency
  exists.
- `tools/check_stack.py` — static analysis that reads `@stack` annotations and the call
  graph (parsed from `call`/`jal` instructions in the asm) to compute worst-case stack
  depth across the binary and assert it fits the reserved stack region.
- `tools/format_log.py` — pretty-prints captured logs (debugging aid for humans; the harness
  uses the structured form directly).

## Risks specific to milestone 1

| Risk | Mitigation |
|------|-----------|
| Espressif boot ROM image header format is undocumented or has undocumented validation | Reverse-engineer from `esp-idf/components/esp_app_format/`; document findings in `docs/hardware/image-header.md`; test against real flash early in the milestone, not at the end. |
| qemu's ESP32-C6 machine model is incomplete or buggy | Mitigate by running `hw` target frequently during development; if `emu` and `hw` diverge, treat `hw` as ground truth and document the qemu gap in `docs/hardware/qemu-gaps.md`. |
| The C6's UART register interface differs subtly from documentation | Same: test against hardware early; document deltas. |
| The Adafruit Feather pinout may differ from a generic ESP32-C6 dev board | Use the official Adafruit schematic only; do not generalize from other boards. |
| SAW + Cryptol for KISS decoder turns out to be heavyweight for the verification value | Acceptable: KISS is a simple state machine and exhaustive symbolic execution (angr) may suffice; document the choice in the function's `@verify` field. |

## Retrospective

(To be added when the milestone reaches `Complete`.)
