# RISC-V-C6

Pure-assembly port of the Reticulum Network Stack to the ESP32-C6 (RV32IMAC).

This is a multi-year, formally-verified, agent-driven asm project. The scope is exhaustive:
every Reticulum function the chip needs to perform, written from scratch in RISC-V assembly,
with mathematical correctness proofs per function before integration.

## Quick orientation

If you are an agent or contributor opening this repo for the first time, read in this order:

1. **[CLAUDE.md](CLAUDE.md)** — operating instructions for any agent or human contributor. Read in full before any work.
2. **[MASTER_PLAN.md](MASTER_PLAN.md)** — vision, scope, milestone roadmap, success criteria.
3. **[docs/adr/](docs/adr/)** — architecture decisions, in numbered order. All Accepted ADRs are binding.
4. **[FUNCTIONS.md](FUNCTIONS.md)** — the function registry. The single source of truth for what exists, what is planned, and what is verified.
5. **[docs/milestones/](docs/milestones/)** — per-milestone specifications. Start with the active milestone.

## Repository layout

```
RISC-V-C6/
├── CLAUDE.md              Operating instructions for agents
├── MASTER_PLAN.md         Multi-year strategic plan
├── FUNCTIONS.md           Function registry (the tracker)
├── README.md              This file
├── docs/
│   ├── adr/               Architecture Decision Records
│   └── milestones/        Per-milestone specifications
├── src/                   Assembly sources (one function per file)
├── tests/                 Test harness (Python, host-side)
├── proofs/                Formal verification scripts and specs (renamed from verify/, see ADR-0008)
├── references/            Vendored reference specs (RFCs, FIPS, papers, upstream Python)
└── toolchain/             Toolchain configuration, linker scripts, board configs
```

## Hardware target

- **Adafruit ESP32-C6 Feather** (4 MB flash, 320 KB HP SRAM, 16 KB LP SRAM, no PSRAM)
- ESP32-C6 SoC: single-core RV32IMAC @ 160 MHz, WiFi 6, BLE 5, 802.15.4

## Status

Project initialized. No assembly written yet. See [FUNCTIONS.md](FUNCTIONS.md) for current
inventory and [docs/milestones/milestone-1.md](docs/milestones/milestone-1.md) for the active work.
