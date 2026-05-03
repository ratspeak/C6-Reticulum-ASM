# Architecture Decision Records

This directory holds the binding architectural decisions for the project. Every ADR captures
a single decision, the context that produced it, and its consequences. ADRs with status
`Accepted` are binding on all code in the repository.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](0001-abi.md) | RISC-V psABI (ILP32) calling convention | Accepted |
| [0002](0002-memory-model.md) | Static-only memory model, no heap | Accepted |
| [0003](0003-wireless-strategy.md) | Wireless strategy: KISS dev → LoRa SPI → native deferred | Accepted (refined by 0011) |
| [0004](0004-diagnostics.md) | Structured UART logging as the permanent diagnostic channel | Accepted (refined by 0008, 0010) |
| [0005](0005-test-harness.md) | Mandatory host-side test harness from day 1 | Accepted |
| [0006](0006-formal-verification.md) | Per-function formal verification, tooling per category | Accepted (partially superseded by 0008) |
| [0007](0007-project-structure.md) | One-function-per-file with machine-readable specs | Accepted (partially superseded by 0008) |
| [0008](0008-naming-toolchain-format.md) | Verifier directory rename, vanilla binutils, hex log timestamps | Accepted |
| [0009](0009-verifier-toolchain.md) | Verifier toolchain — Cryptol/SAW + Binsec/Rel + angr+pcode + Sail-RISCV | Accepted (refines 0006) |
| [0010](0010-usb-serial-jtag-backend.md) | USB-Serial/JTAG as the early-bring-up serial backend | Accepted (refines 0004) |
| [0011](0011-sx1262-lora-target.md) | SX1262 LoRa target for milestone 8 | Accepted (refines 0003) |

## Template

New ADRs use the next available number (`NNNN-<short-kebab-title>.md`). Use this template:

```markdown
# ADR-NNNN: <Title>

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX
- **Date:** YYYY-MM-DD (acceptance date; do not change after acceptance)
- **Supersedes:** ADR-XXXX (if applicable)

## Context

What forced this decision. The constraints, the prior art, the alternatives that were on
the table. Enough that a reader in two years can reconstruct why we considered this at all.

## Decision

The decision itself, stated as a single binding sentence or short paragraph. No hedging.
This is what code in the repository must conform to.

## Consequences

### Positive

What we gain.

### Negative

What we give up. Be honest. Future-us reading this should not be surprised.

### Neutral

Side effects that aren't clearly good or bad but are real.

## Alternatives considered

For each alternative, a one-paragraph description and the reason it was not chosen.

## References

Links to specs, prior art, papers, related ADRs.
```

## Lifecycle

ADRs are immutable after acceptance. To change a decision:

1. Write a new ADR that explicitly supersedes the old one.
2. The new ADR's Status reads `Accepted (supersedes ADR-XXXX)`.
3. The old ADR's Status changes to `Superseded by ADR-YYYY`. A one-line `Supersession reason`
   is added under Status. The body is otherwise unchanged.
4. Update the index above.
5. Search the repo for references to the old ADR number; redirect them.
6. All of the above ships in one atomic commit.

The intent is that the commit log + ADR set together form a complete record of what we believed
and when. Editing accepted ADRs in place defeats this purpose.
