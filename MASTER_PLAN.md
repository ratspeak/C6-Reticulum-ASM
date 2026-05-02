# Master Plan

A pure-assembly implementation of the Reticulum Network Stack on the Adafruit ESP32-C6 Feather,
designed for multi-year incremental delivery, formally verified per function, and structured
for autonomous AI-agent contribution.

This document is strategic. It captures vision, scope, milestones, and risks. It does not
duplicate decisions captured in ADRs or specifications captured in milestone documents.

---

## Vision

Build a Reticulum node whose every instruction is hand-written, formally specified, and
mathematically verified RISC-V assembly. The node runs on a single commodity MCU with no
operating system, no runtime, and no compiled high-level language in the production binary.
The result is a Reticulum implementation with the smallest possible trusted computing base
and the strongest correctness guarantees achievable today.

Three claims must hold at completion:

1. **Coverage.** Every Reticulum function the chip needs to perform — wire format, crypto,
   identity, transport, link, resource, interface — exists as RISC-V asm in this repository.
2. **Correctness.** Every function has either a formal proof of equivalence to a reference
   specification or a complete known-answer-test suite cross-validated against the upstream
   Python implementation. Crypto functions additionally have constant-time proofs.
3. **Self-containment.** The final flashable binary contains no third-party code. Vendor
   register semantics are referenced from documentation; the asm that drives the hardware is
   ours.

---

## Scope

### In scope

- Reticulum protocol stack: packet format, identity, destinations, announces, transport,
  links, resources, channels, ratchets, IFAC.
- Cryptographic primitives required by Reticulum: SHA-256, HMAC-SHA-256, HKDF, AES-256-CBC,
  X25519, Ed25519, secure random.
- At least one wireless interface terminating on the C6: LoRa via SX1276/RFM95 over SPI,
  via a permanent KISS-framed driver path.
- Persistence: flash-resident identity, destination cache, path cache.
- LXMF messaging on top of the Reticulum stack (deferred but in scope).
- Eventually: native ESP32-C6 WiFi, BLE, and 802.15.4 stacks in pure asm. These are massive
  subprojects with their own milestone arc; they are out of the near-term roadmap but in
  the project's overall scope.

### Out of scope

- Other chips. This project targets ESP32-C6 only. Porting to a different RISC-V variant or a
  different vendor's chip would be a separate project.
- C, Rust, or any compiled high-level language in the production binary.
- A graphical user interface, application layer, or end-user product. This is a network stack;
  applications consume it via Reticulum's standard interfaces.
- Re-implementing the upstream Reticulum protocol design. We implement the protocol as
  specified by the canonical Python reference (`upstream/Reticulum/`). Protocol-design changes
  belong upstream, not here.

### Deferred but tracked

These remain in scope for the project's eventual completion. They have no schedule yet.

- Native ESP32-C6 WiFi stack in asm.
- Native ESP32-C6 BLE stack in asm.
- Native ESP32-C6 802.15.4 stack in asm.
- A self-hosting toolchain (assembling RISC-V binaries from source under our own control). The
  initial toolchain dependency on `riscv32-esp-elf-gcc` (used as assembler + linker only) is
  a known trust-base item; eliminating it is a future ADR.

---

## Architecture pillars

These are the cross-cutting decisions that shape every component. Each is captured in detail
in an ADR; this is the orientation summary.

| Pillar | Choice | ADR |
|--------|--------|-----|
| Calling convention | RISC-V psABI (ILP32), strict | [ADR-0001](docs/adr/0001-abi.md) |
| Memory model | Static-only, no heap, link-time layout | [ADR-0002](docs/adr/0002-memory-model.md) |
| Wireless strategy | KISS dev scaffolding → LoRa SPI → native radios deferred | [ADR-0003](docs/adr/0003-wireless-strategy.md) |
| Diagnostics | Structured logging over UART, permanent | [ADR-0004](docs/adr/0004-diagnostics.md) |
| Test harness | Mandatory from day 1, agent-callable, host-side Python | [ADR-0005](docs/adr/0005-test-harness.md) |
| Formal verification | Per-function mandatory, tooling per category | [ADR-0006](docs/adr/0006-formal-verification.md) |
| Project structure | One-function-per-file, machine-readable specs, function registry | [ADR-0007](docs/adr/0007-project-structure.md) |

Additional ADRs will be added as decisions arise. Numbering is monotonic; ADRs are immutable
once accepted (see CLAUDE.md for the supersession protocol).

---

## Milestone roadmap

Each milestone is a vertical slice that lays permanent foundations. The order is dependency-driven:
each builds on the previous and never invalidates it. Estimates are for one experienced asm
developer working full-time, with verification overhead included.

| # | Title | Status | Estimate | Verification milestone |
|---|-------|--------|----------|------------------------|
| 1 | Foundation stack + verifier infrastructure | Active | 8–12 wk | Harness + Sail differential running; KISS codec verified |
| 2 | Cryptographic primitives | Planned | 4–6 mo | Each primitive: KAT + formal equivalence + constant-time |
| 3 | Identity + announce TX | Planned | 3–4 wk | TLA+ for announce state machine; signature verified end-to-end |
| 4 | Flash persistence | Planned | 2–3 wk | Symbolic execution on flash driver; identity round-trip proven |
| 5 | Transport RX (announce processing, paths) | Planned | 4–6 wk | TLA+ for transport state; signature verify on inbound |
| 6 | Link establishment | Planned | 6–8 wk | TLA+ for link state machine; AES session round-trip proven |
| 7 | Resource / channel | Planned | 4–6 wk | Refinement proof against reference behavior |
| 8 | LoRa SPI interface | Planned | 4–6 wk | Driver contracts; symbolic execution; first wireless milestone |
| 9 | LXMF | Planned | 6–8 wk | TLA+ for router; message round-trip proven |
| Later | Native WiFi / BLE / 802.15.4 in asm | Deferred | 12+ mo each | Each gets its own ADR and roadmap |

**Realistic total to milestone 8 (first standalone wireless node), single dev:** 24–36 months.

Per-milestone specifications live in [docs/milestones/](docs/milestones/). The active spec
is the source of truth for what the current milestone delivers; this table is orientation only.

---

## Risk register

Risks that threaten the multi-year arc. Reviewed at every milestone boundary.

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Constant-time crypto in pure asm proves harder than estimated | Medium | High | Vendored references from HACL\*, fiat-crypto, BearSSL; per-primitive ADR if scope grows |
| Espressif boot ROM behavior poorly documented | High | Medium | Reverse-engineer from ESP-IDF source; capture findings in `docs/hardware/boot.md`; pin a specific bootrom revision |
| Toolchain dependency on `riscv32-esp-elf-gcc` becomes a maintenance burden | Medium | Medium | Pin version in `toolchain/versions.lock`; monitor for binutils-only alternative; deferred-but-tracked self-hosting milestone |
| Reticulum protocol changes upstream during the multi-year build | Medium | Medium | Pin the upstream commit at each milestone start; protocol-version negotiation in TLA+ specs |
| Formal verification effort blows up on a single primitive | Low | High | Hard cap of 3 months per primitive before re-scoping; fall back to KAT + extensive symbolic execution if a proof is intractable |
| AI agents introduce subtle correctness regressions | Medium | High | Verifier blocks merges; FUNCTIONS.md tracks per-function status; PR diff review required for all changes |
| Hardware revision (new ESP32-C6 silicon) changes register layout | Low | Medium | Pin to a specific revision in `toolchain/board.md`; abstract register addresses through a single header |
| Single-developer bus factor | High | High | Documentation discipline (this plan, ADRs, function specs) is the primary mitigation |

---

## Success criteria

The project is considered complete (for its near-term arc, milestones 1–8) when:

1. A standalone Adafruit ESP32-C6 Feather, flashed with this repository's binary, can:
   - Generate and persist its own Reticulum identity.
   - Emit valid signed announces over an attached SX1276 LoRa module.
   - Receive and validate announces from peer Reticulum nodes (Python `rnsd`, microReticulum, rsReticulum).
   - Establish a link with a peer and exchange encrypted data packets.
2. Every function in the compiled binary is listed in FUNCTIONS.md with status `verified`.
3. Every cryptographic primitive has passed its constant-time verifier on the as-built binary.
4. The repository is reproducible from source: a fresh clone + documented toolchain produces
   a byte-identical binary.
5. All ADRs from 0001 through the latest accepted are reachable and self-consistent.

The deferred-but-tracked items (native WiFi/BLE/802.15.4) extend the project beyond this; their
own success criteria will be defined when each is activated.

---

## How this plan stays current

This plan is reviewed at every milestone boundary. The review:

1. Updates the roadmap table to reflect actual completion status.
2. Adds a `Retrospective` paragraph to the completed milestone's spec (not this plan).
3. Adjusts subsequent estimates if the completed milestone diverged significantly.
4. Reviews the risk register; adds new entries, marks materialized risks, removes resolved ones.
5. Files an ADR if any architectural pillar needs to change.

If the project is paused or hibernated, this plan and CLAUDE.md remain the wake-up document.
A contributor (human or agent) returning after months should be able to read these two files
and identify the next concrete piece of work without conversation context.
