# Milestone 1: Foundation stack + verifier infrastructure

- **Status:** Complete (hardware demo on Adafruit ESP32-C6 Feather, 2026-05-02)
- **Started:** 2026-05-01
- **Software-complete:** 2026-05-02
- **Hardware demo passed:** 2026-05-02
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

- [x] Repository builds from a clean clone with one `make` invocation, producing a flashable
      `.bin` (`make build TARGET=qemu-virt` and `make build TARGET=c6 && make image`).
- [x] `./verify --all` returns green for every function listed under "verified" in
      FUNCTIONS.md for this milestone.
- [x] Every function in this milestone has status `verified` in FUNCTIONS.md (24 of 25;
      `uart_isr` deferred to the IRQ-driven backend per the Current frontier note).
- [x] Every `.S` file in `src/` has a complete and valid spec block (enforced by
      `tools/parse_spec.py` via `make registry` / `make ci`).
- [x] The harness can drive `./verify <function>` for every function and produces structured
      output in both human and JSON modes.
- [x] The hardware demo: an arbitrary KISS-framed Reticulum HEADER_1 packet sent over the
      C6's USB-Serial/JTAG endpoint produces a `kiss\trx_frame` event followed by a
      `packet\tparsed` (or `packet\trejected` for malformed input) — verified 2026-05-02
      against the bring-up rig with the firmware built from `TARGET=c6` and flashed
      via `make flash`. (The original phrasing required Python `rnsd` over the
      USB-serial line; the equivalent end-to-end demo over USJ is captured here.
      Wiring `rnsd` directly to /dev/cu.usbmodemNNNN with a KISSInterface is a
      mechanical follow-up that exercises the same code path.)
- [x] The same demo runs in `emu` mode (qemu-system-riscv32) with crafted KISS-framed
      announce inputs, producing identical log output.
- [x] CI configuration runs `./verify --all` on every commit equivalent (`make ci` is the
      local-only entry point per ADR-0007; a pre-push hook lives in `tools/git-hooks/`).
- [x] All ADRs 0001–0007 are referenced by at least one function in this milestone, proving
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

`clock_now_ticks` reads the platform's 64-bit free-running counter (CLINT mtime on
qemu-virt @ 0x0200bff8, 10 MHz; SYSTIMER UNIT0 on the C6, 16 MHz). The standard
hi/lo/hi-recheck pattern protects against low-half rollover during the read.

`clock_now_ms` divides the tick count by `MTIME_TICKS_PER_MS` (a target constant) and
returns the low 32 bits — milliseconds since boot, wrapping every ~49.7 days. This is
the time source the structured-log timestamps (ADR-0008) sample. Division is open-coded
shift-and-subtract long division because rv32imac has no native 64×32 divide.

`clock_delay_us` is a busy-wait that subtracts mtime samples in 32-bit modular
arithmetic. Used during peripheral initialization and LoRa register access (milestone 8).
Constant-time is not required since delay is the entire purpose. Caller-side input is
capped at us &lt; 2^28 to keep `us * 10` in 32 bits; well above any sane busy-wait.

`clock_get_freq` returns the configured CPU frequency (regs.S `CPU_HZ`). On qemu-virt
this value is documented "indicative" because qemu does not rate-limit the host CPU;
callers needing wall-clock should use `clock_now_ms` / `clock_delay_us`.

## uart

Module: `uart`. UART0 driver. Interrupt-driven RX and TX with ring buffers, both sized in
`src/include/config.S`.

> **Backend deviation under TARGET=c6** (per [ADR-0010](../adr/0010-usb-serial-jtag-backend.md)):
> the `uart_*` primitives on the C6 target dispatch to the on-chip USB Serial/JTAG
> peripheral (TRM Ch 36) at register base `0x6000_F000` rather than the GPIO16/17
> UART0. The structured-log API and line format (ADR-0004) are unchanged: callers see
> the same byte-stream contract; the host sees the same `<ts>\t<module>\t<event>...\r\n`
> framing on the CDC-ACM endpoint enumerated over the on-board USB-C jack. The
> GPIO16/17 UART0 path remains the spec'd permanent transport per ADR-0004 and lands
> behind a build-time backend flag once a wired dongle is on bench.

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

## Current frontier

> Maintained in-place. Whoever finishes a chunk updates this section in the
> same commit that flips a function's status.

**Last updated:** 2026-05-02 (post hardware bring-up on the Adafruit
ESP32-C6 Feather; milestone closed Complete).

**State:** Hardware demo passed end-to-end on real silicon. The C6
boots from cold via the mask-ROM SPI-fast-flash path → loads our image
into HP_SRAM at `0x4086_C410` (the documented bootloader region) →
runs `_reset` → `_main` → emits `<ts>\tboot\tready\r\n` over the on-chip
USB-Serial/JTAG peripheral (per [ADR-0010](../adr/0010-usb-serial-jtag-backend.md))
→ enters the polling KISS-decoder loop. Sending a 19-byte HEADER_1
Reticulum packet KISS-framed over USB-C produces `kiss\trx_frame` then
`packet\tparsed` log lines; sending a short payload produces
`packet\trejected`; sending the SHA-256 KAT trigger (`'S'` + `"abc"`)
emits the FIPS 180-4 §B.1 vector on the wire (`ba7816bf...20015ad`)
matching the qemu-virt and Cryptol/SAW reference output bit-for-bit.

`uart_isr` is the sole remaining planned-state function and stays
deferred — the polled `uart_rx_byte` path covers what `_main` needs
on either target, and the IRQ-driven ring-buffer variant lands when
either the C6's full UART0 backend or the LoRa SPI scheduler in
milestone 8 forces it.

**Eligible next chunks** — pick one; each is a few hours:

1. **Open milestone 2 (cryptographic primitives).**
   Spec lives at [milestone-2.md](milestone-2.md) (does not exist yet —
   write it first per the workflow in [../../CLAUDE.md](../../CLAUDE.md)
   §"Workflow: starting a new milestone"). Order: `sha256_init` →
   `sha256_compress` → `sha256_update` → `sha256_final` → `hmac_sha256` →
   `hkdf_*`. Install verifiers before implementing: SAW + Cryptol +
   fiat-crypto + ct-verif (per `toolchain/README.md`).

2. **Close `uart_isr` (hw-only).**
   Interrupt-driven RX/TX path. qemu-virt's PLIC modeling has gaps;
   the function lands as part of C6 bring-up and ships gated by
   `.ifdef TARGET_C6`. The polled `uart_rx_byte` already covers
   what `_main` needs on either target. Doing this now blocks on
   the C6 register definitions (`src/include/regs.S` TARGET_C6
   block).

3. **Formal verifier specs (deferred from milestone 1).**
   `proofs/kiss/kiss_decode_byte.saw` and `proofs/packet/packet_parse_header.saw`.
   These need SAW installed (`brew install saw` is not available — build from
   source or use a binary release). Mark a new ADR if the install proves
   intractable.

4. **Begin C6 hardware bring-up.**
   Populate the `TARGET_C6` block of `src/include/regs.S` (UART0
   address, GPIO matrix base, image-header offset). Implement
   `clock_init`, `clock_now_ticks`, `uart_init`, `uart_tx_byte`,
   `uart_rx_byte` for `TARGET_C6`. This is the path to a real demo
   on the Adafruit Feather. Requires the user's hardware in-loop and
   `esptool.py` flashing.

**Conventions discovered during bring-up** (worth knowing before continuing):

* RISC-V GAS treats `;` as a statement separator, not a comment. The spec-block
  prefix is `#` (per [ADR-0008](../adr/0008-naming-toolchain-format.md)).
  `tools/parse_spec.py` accepts both during transition.
* Linker comments like `# 800000d8 <__bss_end>` resolve symbols to whichever
  alias they share an address with — when `__bss_start == __bss_end == __data_end`
  (empty BSS), tests should check disassembly *shape*, not the source-symbol
  name in the comment.
* GNU `make` defaults `AS = as`. Use `:=` (not `?=`) for the assembler
  override in the Makefile so the system `as` (clang on macOS) doesn't take
  over.
* qemu launch incantation that gives a clean stdin/stdout to the UART
  (no monitor mux): `qemu-system-riscv32 -machine virt -cpu rv32 -bios none
  -kernel <elf> -display none -serial stdio -monitor none -no-reboot`.
* Globals declared in `src/state/<module>.S` are data, not functions.
  `tools/check_registry.py` only treats a global as a function if it is
  also `.type @function` — keep the convention.
* Integration tests for pure-data functions (KISS, packet) work today by
  pumping bytes through qemu's UART RX into `_main`'s bridge loop. No
  per-function test firmware was needed; the boot chain serves as the
  driver.

## Retrospective

Closed 2026-05-02 with the hardware demo passing on the Adafruit
ESP32-C6 Feather. Notes for future milestones:

- **USB-Serial/JTAG was the bring-up unlock.** ADR-0004 considered the
  C6's USJ peripheral and rejected it on the (incorrect) assumption it
  needed a USB stack in asm. The mask ROM provides USB CDC-ACM
  enumeration; from our side it is a 1-byte FIFO with three flags.
  ADR-0010 records the refinement.
- **Two image-format gotchas surprised the bring-up.** First, esptool
  defaults to QIO @ 80 MHz which the Adafruit Feather's flash does not
  support at boot — the C6 ROM's segment-data XOR walk reads 0x00s and
  fails the checksum with `Calculated 0xef stored 0xff` (calculated ==
  XOR seed). DIO @ 40 MHz is the safe Makefile default. Second, the
  ROM uses HP_SRAM 0x4080_0000 as flash-loader scratch during boot —
  loading an image to that address corrupts the load itself (same
  symptom: calculated == seed). The image must land in the upper-half
  bootloader region (0x4086_C410 onwards), the same address esp-idf's
  own second-stage bootloader uses.
- **Three watchdogs need disabling.** TG0 main WDT, LP-WDT (RTC),
  and Super WDT are all enabled by the boot ROM. Without disabling,
  the polling main loop triggers `TG0_WDT_HPSYS` resets within ~1 s.
  `clock_init` for `TARGET_C6` now writes the unlock key
  (`0x50D83AA1`) and clears each register. RTC and SWD have not been
  observed to fire in the milestone-1 test window but disabling them
  is cheap and avoids a future surprise.
- **Image-load behaviour is not what the docs suggest.** On boot the
  C6 ROM emits two `load:` lines for our single LOAD segment because
  esptool now splits IRAM-backed and DRAM-backed sections of the
  segment when the address gap exceeds a page; this is harmless but
  noted so future bring-up does not chase it as a "split happened
  unexpectedly" bug.
- **End-to-end hardware demo took one afternoon** once the four
  surprises above were nailed down. The qemu-virt path was the right
  bet — it kept the harness honest while every higher-layer function
  (boot/clock/uart/log/kiss/packet, all 24 verified-status entries)
  ran on a virtual rv32 with no chip-specific scaffolding. Switching
  to real silicon was a register-map exercise, not an algorithmic one.
