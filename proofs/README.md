# Verification

Per-function formal verification specs and the policy that governs them. The policy is
captured in [ADR-0006](../docs/adr/0006-formal-verification.md) and the concrete tool
choices in [ADR-0009](../docs/adr/0009-verifier-toolchain.md); this README is the
practical companion.

## Layout

```
proofs/                     (renamed from verify/, see ADR-0008)
├── README.md               (this file)
├── boot/                   register-state contracts for boot functions
├── clock/                  contracts for clock setup
├── uart/                   contracts for UART driver
├── log/                    contracts for log primitives
├── kiss/                   SAW or angr scripts for KISS codec
├── packet/                 SAW for packet header parser
├── crypto/                 (added in milestone 2) SAW + Cryptol for crypto primitives
├── identity/               (added in milestone 3) TLA+ for identity state
├── transport/              (added in milestone 5) TLA+ for transport
├── link/                   (added in milestone 6) TLA+ for link state
└── output/                 (gitignored) verifier outputs and intermediate files
```

## Tooling per category

The concrete tool choices are pinned in [ADR-0009](../docs/adr/0009-verifier-toolchain.md).
Per-tier mapping:

| Tier | Tool | What it proves | Spec file |
|------|------|----------------|-----------|
| **A** Algorithmic | Cryptol 3.5.0 + SAW 1.5 | Cryptol model matches FIPS/RFC algebraic spec | `.cry`, `.saw` |
| **B** Constant-time | Binsec 0.11.1 (`-isa riscv32 -checkct`) | No secret-dependent control flow or memory access on RV32 ELF | `.bsc` |
| **C** Binary equivalence | angr 9.2.213 + pypcode (`RISCV:LE:32:RV32IMC`) | RV32 binary computes the Cryptol-spec function on the symbolic input domain | `.py` |
| **D** State machine | TLA+ Tools 2.19 (`tlc`) | Asm trace refines the TLA+ spec | `.tla`, `.cfg` |
| **E** ISA ground truth | Sail 0.20.1 + `riscv/sail-riscv` model | (reference, not run per-PR) | (vendored) |

| Category | Required tiers |
|----------|----------------|
| Crypto primitive (`@module: crypto/*`) | A + C; **B if `@ct: required`** |
| Pure data transformation (KISS, parser, hex) | C |
| State machine (transport, link, resource) | D + C |
| Hardware driver | C with hardware-register model |
| Memory operation | C |
| Glue / control flow | C (reachability + termination only) |

Tier C-future (full SAW-on-RV32 equivalence via `macaw-riscv` + a forked
`saw-script`) is documented in ADR-0009 §"Tier C path forward". Until then,
crypto primitives carry both Tier A (algorithmic equivalence) and Tier C
(bounded angr exploration) — Tier C is a strong supplement to KAT but is not
a full equivalence proof in the SAW sense, and that distinction is honest in
each spec block.

## Invocation

`./verify <function_name>` from the repository root dispatches to every verifier in
the function's `@verify` field. The field is a comma-separated list of paths
(per ADR-0009); each suffix selects its backend.

- `@verify: proofs/crypto/sha256/sha256_init.cry, proofs/crypto/sha256/sha256_init.saw, proofs/crypto/sha256/sha256_init.py`
  — Tier A (Cryptol typecheck + SAW driver) plus Tier C (angr binary
  equivalence). All three must pass.
- `@verify: proofs/transport/transport_state.tla` — Tier D, runs TLC with that spec.
- `@verify: kat-only; <rationale>` — only KAT vectors are required (typical
  for glue/control-flow). The rationale is mandatory.

## Verification escalation

If a function's full verification has not discharged after 3 months of focused effort:

1. Open an issue (or session note) describing what blocked the proof.
2. Decide one of:
   - Split the function into smaller pieces, each separately verifiable.
   - Choose a different algorithm with a known verification path.
   - Accept reduced obligation (e.g., KAT + extensive symbolic execution instead of full
     equivalence proof). Documented in a new ADR.
3. Update the function's `@verify` field to match the new obligation.

Never silently lower the bar. The reduced-obligation ADR is the audit trail.

## Constant-time policy

For any function with `@ct: required`:

1. The function's body must contain no secret-dependent branches.
2. The function's body must contain no secret-dependent memory accesses.
3. The function must complete in a number of cycles independent of secret inputs.
4. The constant-time verifier (ct-verif or Binsec/Rel) must pass on the as-built binary.
5. No log emission inside the secret-handling section. Logging at function entry and exit
   is permitted (it cannot leak secrets if it logs only public data like a tag).

A function failing any of these may not be marked `verified`, regardless of its KAT or
equivalence results.

## Differential testing

For functions where a reference implementation exists (Reticulum's Python source, FIPS test
vectors, RFC test vectors), the harness runs the same input through both and asserts byte-
identical output. This is not formal verification but is a strong correctness signal and is
required in addition to (not instead of) the formal obligation.

The `oracle` target in the test harness is the differential-testing entry point. See
[../tests/README.md](../tests/README.md).
