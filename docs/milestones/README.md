# Milestones

Per-milestone specifications. Each milestone is a vertical slice that lays permanent
foundations: nothing is built only to be discarded later.

The roadmap is in [MASTER_PLAN.md](../../MASTER_PLAN.md). This directory holds the detailed
spec for each milestone.

## Status

| # | Title | Status | Spec |
|---|-------|--------|------|
| 1 | Foundation stack + verifier infrastructure | Complete (2026-05-02) | [milestone-1.md](milestone-1.md) |
| 2 | Cryptographic primitives | Complete (2026-05-02) | [milestone-2.md](milestone-2.md) |
| 3 | Identity + announce TX | Complete (2026-05-03) | [milestone-3.md](milestone-3.md) |
| 4 | Flash persistence | Complete (2026-05-03) | [milestone-4.md](milestone-4.md) |
| 5 | Transport RX | Complete (2026-05-03) | [milestone-5.md](milestone-5.md) |
| 6 | Link establishment | Complete (2026-05-03) | [milestone-6.md](milestone-6.md) |
| 7 | Resource / channel | Complete (2026-05-03) | [milestone-7.md](milestone-7.md) |
| 8 | LoRa SPI interface | Complete (2026-05-03) | [milestone-8.md](milestone-8.md) |
| 9 | LXMF foundation | Active (2026-05-03) | [milestone-9.md](milestone-9.md) |

Each milestone spec is written when the milestone is activated, not in advance. Pre-writing
specs invites them to drift from reality before they are used.

## Template

```markdown
# Milestone N: <Title>

- **Status:** Active | Complete | Cancelled
- **Started:** YYYY-MM-DD
- **Completed:** YYYY-MM-DD (when applicable)
- **Estimate:** <weeks/months>

## Goal

One paragraph: what this milestone delivers and why it is permanent.

## Deliverables

A table of components, each with a short description and the section of this spec that
specifies it in detail.

## Definition of done

A bullet list of objectively verifiable conditions. Every condition either passes or fails.
The milestone is `Complete` only when every condition passes.

## Per-component sections

One section per component. Each section names the functions involved (with FUNCTIONS.md
status), the spec block templates, the test plan, the verifier plan, and any hardware or
toolchain dependencies.

## Risks specific to this milestone

Risks that did not appear in MASTER_PLAN.md's general risk register.

## Retrospective (added at completion)

What diverged from the plan and why. Lessons for the next milestone. Do not edit the body
of the spec; add this section at the end.
```
