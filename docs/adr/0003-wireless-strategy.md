# ADR-0003: Wireless strategy — KISS dev → LoRa SPI → native deferred

- **Status:** Accepted
- **Date:** 2026-05-01

## Context

The Adafruit ESP32-C6 Feather has three native radios: WiFi 6, BLE 5, and 802.15.4. None of
their firmware/MAC interfaces are documented outside the ESP-IDF source. Implementing any of
them in pure assembly is a multi-year subproject in its own right. We need a wireless strategy
that produces a real, useful Reticulum node within the project's near-term horizon, while
keeping the door open to native radio implementations as a long-term goal.

A note on terminology that earlier drafts of this plan got wrong: in Reticulum, an "RNode" is
specifically a LoRa-equipped serial device that exposes a KISS interface to a host computer
running the Reticulum stack. The host runs Reticulum; the RNode is a dumb radio modem. Our C6
is intended to be the host (running the stack itself in asm), so describing it as "RNode-style"
or "tethered RNode" was a category error. This ADR uses the corrected vocabulary.

The candidate end-states for "where does this node's wireless connectivity come from":

- **(A) KISS-over-USB-serial peer.** The C6 runs Reticulum and uses a serial line to a peer
  Reticulum instance (typically `rnsd` on a host PC) as its only interface. The C6 is a
  Reticulum node, but its only path to the network is the host. Useful for development; not
  useful as a standalone product.
- **(B) External LoRa module on SPI.** The C6 runs Reticulum and drives an SX1276/RFM95
  LoRa module over its SPI bus. The C6 becomes a self-contained Reticulum LoRa node — the
  same kind of device microReticulum runs on, but in pure asm.
- **(C) Native ESP32-C6 radio (WiFi, BLE, or 802.15.4) in pure asm.** The C6 uses its own
  on-die radios. No external module. The most capable end-state, and the most demanding to
  build, since the firmware/MAC interface is undocumented.

## Decision

Adopt all three, in this order, with the following roles:

1. **Mode (A) is development scaffolding only.** The KISS-over-USB-serial path exists from
   day one and is the only "interface" the C6 has through milestones 1–7. The test harness
   uses it. The C6 in this mode is not a product; it is a node connected to the test rig. We
   do not invest in features that exist solely to make mode (A) more useful as an end product.

2. **Mode (B) is the primary near-term wireless target.** Milestone 8 implements the SPI
   driver and the SX1276 register driver. At that point the C6 becomes a real, standalone
   Reticulum LoRa node — capable of joining a Reticulum mesh on its own, with no host PC
   tether. This is the first milestone where the device is independently useful in the world.

3. **Mode (C) is in scope for the project's overall completion but deferred indefinitely.**
   Each native radio (WiFi, BLE, 802.15.4) will be its own milestone arc with its own ADRs,
   activated only after milestones 1–9 are complete and the project chooses to take on the
   next-generation work. Estimated cost: 12+ months per radio, single dev. No work on these
   begins until they are explicitly activated by a future milestone.

## Consequences

### Positive

- Clear, unambiguous near-term target (LoRa via SPI in milestone 8) — the project produces
  a functioning standalone Reticulum node within the realistic 24–36 month window.
- Mode (A) gives us an automated, hardware-cheap test path through the entire stack-building
  phase. We do not need a working radio to validate the protocol layers.
- Mode (C) is preserved as an end goal without committing schedule to it. The exhaustive-port
  vision of the project remains intact.

### Negative

- Mode (A) means the C6 is not "useful" in any product sense until milestone 8. This is fine
  for our purposes (we are building a stack, not a product) but should be communicated to
  any contributor who joins expecting a demo earlier.
- We commit to an external LoRa module dependency. The SX1276/RFM95 interface is well-
  documented and stable, but it is a hardware dependency the project must source.
- Native-radio work is so far in the future that the chip's silicon may have a successor
  by the time we get there. We accept this risk; the reusable scaffolding (boot, UART, KISS,
  packet, crypto, identity, transport, link) is the bulk of the work and is silicon-agnostic
  within the RISC-V family.

### Neutral

- The KISS codec built in milestone 1 serves both mode (A) (over USB-serial) and mode (B)
  (the LoRa interface uses the same KISS framing for the host side). It is permanent
  infrastructure regardless of which mode is active.

## Alternatives considered

**Skip (A), go straight to (B).** Reject. We cannot test the protocol stack without an
interface. Without (A) we would need a working LoRa module on day one and would be debugging
asm correctness and radio behavior simultaneously. Splitting them is essential.

**Pure-asm WiFi as the first wireless target.** Reject. The work is enormous (multi-year),
the documentation gap is severe, and the resulting code is locked to ESP32-C6 silicon. LoRa
gives us a wireless node at a fraction of the cost and a reusable skill set.

**Drop mode (C) from project scope entirely.** Reject. The project's stated end goal is an
exhaustive asm port of every function this chip needs. Removing the radios from scope would
contradict that. Deferring them indefinitely without dropping them preserves the goal.

## References

- ADR-0007 — project structure, which the modular per-interface design supports.
- `references/upstream/Reticulum/RNS/Interfaces/` — the canonical Python interface implementations,
  cross-referenced when implementing each interface in asm.
- SX1276 datasheet (Semtech), to be vendored at `references/sx1276-datasheet.pdf` before
  milestone 8.
