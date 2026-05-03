# Milestone 8: LoRa SPI Interface

- **Status:** Active
- **Started:** 2026-05-03
- **Estimate:** 4-6 weeks

## Goal

Turn the ESP32-C6 from a USB-serial development node into a standalone
Reticulum LoRa node by driving an external SX1262 transceiver over SPI. This
milestone adds the permanent GPIO/SPI hardware foundation, a bounded SX1262
command driver, and a Reticulum-facing LoRa interface that can transmit and
receive one packet at a time without heap allocation.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Hardware contract and pin map | [hardware contract](#hardware-contract) | Forever |
| GPIO helpers | [gpio helpers](#gpio-helpers) | Forever |
| SPI transfer path | [spi-transfer-path](#spi-transfer-path) | Forever |
| SX1262 command driver | [sx1262-command-driver](#sx1262-command-driver) | Forever |
| LoRa packet TX/RX | [lora-packet-txrx](#lora-packet-txrx) | Forever |
| Reticulum interface glue | [reticulum-interface-glue](#reticulum-interface-glue) | Development path through LXMF |
| Interface state proof | [verifier plan](#verifier-plan) | Forever |

## Definition of Done

- [x] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-8 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `docs/hardware/lora.md` pins the Wio-SX1262 V1.0 header-carrier wiring,
      voltage assumptions, reset/BUSY/DIO1 semantics, SPI mode, clock bounds,
      and reference provenance before production asm depends on those values.
- [x] GPIO helpers configure and sample the exact C6 pins used for SX1262
      CS, RESET, BUSY, and DIO1 without disturbing UART0 or USB-Serial/JTAG
      diagnostics.
- [x] SPI init and transfer support bounded full-duplex byte exchange on the
      selected ESP32-C6 SPI peripheral, with deterministic timeout/error
      statuses on qemu and TARGET_C6.
- [ ] SX1262 reset/init verifies the radio command path by reaching standby
      from cold reset and validating at least one readback/status command on
      hardware.
- [x] TX accepts one bounded Reticulum packet, writes it into the SX1262 FIFO,
      starts transmit, observes TX done or timeout, and never overruns the
      configured LoRa payload limit.
- [x] RX polls DIO1/IRQ state, reads one received frame into static storage,
      distinguishes no-packet, received, CRC/error, and overflow statuses, and
      exposes the raw Reticulum packet to the existing parser path.
- [x] `_main` initializes the native LoRa interface during boot, preserves the
      USB/KISS development path with a nonblocking UART pump, and polls one
      LoRa frame per idle loop.
- [x] A TLA+ LoRa interface state model covers reset, configure, idle, TX,
      TX timeout, RX, RX error, and recovery traces.
- [ ] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`,
      `pytest --hardware tests/hardware/`, and `./verify <fn>` pass for every
      function added or modified in this milestone.

## Scope

Milestone 8 proves the first standalone wireless path. It does not add native
ESP32-C6 WiFi/BLE/802.15.4, packet routing policy changes, IFAC, regional
regulatory enforcement, adaptive data rate, CAD/channel activity detection,
frequency hopping, persistent interface configuration, or LoRaWAN.

The first LoRa configuration is a static bench configuration. Frequency,
bandwidth, spreading factor, coding rate, TX power, preamble, and sync word
must be explicit constants or documented config inputs; no implicit defaults
may hide in the driver.

## Hardware Contract

Document:

- `docs/hardware/lora.md`

Responsibilities:

1. Record the physical module, pin map, power assumptions, SPI peripheral,
   CS/RESET/BUSY/DIO1 GPIOs, and bench wiring for the selected Wio-SX1262
   V1.0 header carrier.
2. Vendor or cite acquisition steps for the SX1262 datasheet and module
   schematic/pinout in [references/README.md](../../references/README.md).
3. Define the qemu hardware model surface used by tests before the asm driver
   reaches into C6 peripheral registers.

## GPIO Helpers

Module: `interface/gpio`.

Functions:

- `gpio_config_output`
- `gpio_config_input`
- `gpio_write`
- `gpio_read`

Responsibilities:

1. Configure only documented pins and preserve diagnostic UART/USB behavior.
2. Provide stable negative errno returns for invalid pin numbers or unsupported
   modes.
3. Keep register writes explicit enough for the hardware contract verifier to
   model.

## SPI Transfer Path

Module: `interface/spi`.

Functions:

- `spi_init`
- `spi_transfer`

Responsibilities:

1. Initialize the selected C6 SPI peripheral for SX1262-compatible mode.
2. Transfer bounded byte spans from static/caller buffers without heap
   allocation.
3. Return deterministic success, invalid, overflow, and timeout statuses.

## SX1262 Command Driver

Module: `interface/lora`.

Functions:

- `sx1262_reset`
- `sx1262_command_write`
- `sx1262_command_read`
- `sx1262_init`

Responsibilities:

1. Reset the radio through the documented RESET pin and wait for BUSY to clear.
2. Implement bounded command write/read transactions over `spi_transfer`.
3. Configure the static milestone-8 LoRa parameters and enter standby/receive
   state with stable error reporting.

## LoRa Packet TX/RX

Module: `interface/lora`.

Functions:

- `sx1262_send_frame`
- `sx1262_poll_receive`

Responsibilities:

1. Bound frame lengths to the selected LoRa payload maximum and static SRAM
   buffers.
2. For TX, write FIFO payload, start transmit, and return TX done or timeout.
3. For RX, detect packet IRQ, read payload/status, reject overflow/CRC errors,
   and leave a raw Reticulum packet view for upper layers.

## Reticulum Interface Glue

Module: `interface/lora`.

Functions:

- `lora_interface_init`
- `lora_interface_send`
- `lora_interface_poll`

Responsibilities:

1. Initialize the radio interface after identity/transport/link state is ready.
2. Send raw Reticulum packets produced by existing stack paths.
3. Poll one received LoRa frame per call and pass valid raw packets into the
   existing packet/transport/link dispatch path.
4. Wire `_main` to initialize this interface during boot and poll it without
   blocking the existing USB/KISS command path.

## Verifier Plan

- TLA+ model [proofs/lora/lora_interface_state.tla](../../proofs/lora/lora_interface_state.tla)
  for LoRa reset/configure/TX/RX/error recovery traces.
- Hardware-register source contracts for GPIO and SPI helpers.
- Direct qemu tests against a deterministic SPI/SX1262 model for command,
  timeout, overflow, and IRQ transitions.
- Hardware tests against the attached SX1262 module for reset/readback,
  standby/configure, TX done, and RX/error handling where bench equipment
  permits.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| SX1262 documentation is not vendored yet | Make `docs/hardware/lora.md` and reference provenance a first deliverable before driver code claims close. |
| ESP32-C6 SPI register setup may require clock/reset details not yet modeled | Start with `spi_init` plus a qemu hardware model; document every register source in the hardware contract. |
| Hardware tests need a second LoRa peer or RF test setup | Split command/readback tests from RF packet tests; allow deterministic qemu model coverage for paths that need a peer until bench hardware is present. |
| Airtime/regulatory behavior is easy to over-scope | Keep milestone 8 to a static bench configuration and basic timeout/error statuses; regional policy and airtime accounting wait for a later interface hardening milestone. |
