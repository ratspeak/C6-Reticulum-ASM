# ADR-0011: SX1262 LoRa target for milestone 8

- **Status:** Accepted (refines ADR-0003)
- **Date:** 2026-05-03
- **Supersedes:** ADR-0003 chip choice only

## Context

ADR-0003 selected an external SX1276/RFM95 LoRa module for the first
standalone wireless milestone. Before milestone 8 activated, the bench
hardware changed: the module on hand is a Seeed Wio SX1262 LoRa module.

SX1262 still satisfies ADR-0003's architectural decision. It is an external
LoRa transceiver driven over SPI, so the Reticulum stack remains on the
ESP32-C6 and the native ESP32-C6 radios remain deferred. The material
difference is the radio driver layer: SX1262 is command-oriented and has a
BUSY line plus DIO1 IRQ, while SX1276/RFM95 exposes a flatter register-file
interface.

## Decision

Milestone 8 targets an SX1262 LoRa transceiver over ESP32-C6 SPI instead of
SX1276/RFM95. Code, tests, verifier models, hardware contracts, and reference
inventory for milestone 8 must use SX1262 naming and semantics.

## Consequences

### Positive

- The milestone matches the hardware available for bring-up.
- The SPI and Reticulum interface layers remain reusable for later LoRa
  modules.
- SX1262's BUSY and DIO1 signals make hardware-state tests explicit instead of
  relying only on timing assumptions.

### Negative

- ADR-0003's SX1276/RFM95 register-driver wording is stale for milestone 8.
- Existing SX1276/RFM95 examples do not map directly onto the SX1262 command
  interface.
- The SX1262 datasheet and board pinout must be vendored or documented before
  implementation claims can close.

### Neutral

- Reticulum's higher-level LoRa interface parameters remain the same kind of
  inputs: frequency, bandwidth, transmit power, spreading factor, coding rate,
  and airtime limits.
- Native ESP32-C6 WiFi, BLE, and 802.15.4 work remains deferred.

## Alternatives considered

**Keep SX1276/RFM95 as the milestone target.** Rejected. It would force the
project to target hardware that is not on the bench, delaying hardware
verification and violating the milestone's standalone-wireless goal.

**Make milestone 8 radio-chip-agnostic.** Rejected for the implementation
slice. A generic SPI foundation is useful, but closing the wireless milestone
requires a concrete transceiver, IRQ model, and hardware test plan.

**Skip LoRa and start native ESP32-C6 radios.** Rejected for the same reasons
as ADR-0003: the native radio interfaces are a separate, much larger project
arc.

## References

- [ADR-0003](0003-wireless-strategy.md) -- wireless strategy.
- [docs/open-questions.md](../open-questions.md#oq-5-lora-chip-choice--sx1262-decided-2026-05-02)
  -- original SX1262 decision note.
- Reticulum manual: `interfaces/rnode-lora-interface.md`, for the LoRa
  parameter set used by upstream Reticulum interfaces.
- Upstream Reticulum: `RNS/Interfaces/RNodeInterface.py`, for current RNode
  LoRa interface configuration fields and MTU constraints.
