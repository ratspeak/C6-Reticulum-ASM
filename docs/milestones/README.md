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
| 3 | Identity + announce TX | Active (2026-05-03) | [milestone-3.md](milestone-3.md) |
| 4 | Flash persistence | Planned | (spec written when activated) |
| 5 | Transport RX | Planned | (spec written when activated) |
| 6 | Link establishment | Planned | (spec written when activated) |
| 7 | Resource / channel | Planned | (spec written when activated) |
| 8 | LoRa SPI interface | Planned | (spec written when activated) |
| 9 | LXMF | Planned | (spec written when activated) |

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
