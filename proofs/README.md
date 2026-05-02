# Verification

Per-function formal verification specs and the policy that governs them. The policy is
captured in [ADR-0006](../docs/adr/0006-formal-verification.md); this README is the
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

| Category | Tools | Spec file extension |
|----------|-------|---------------------|
| Crypto primitive | SAW + Cryptol; fiat-crypto for field arithmetic; ct-verif for constant-time | `.saw`, `.cry` |
| Pure data transformation | SAW for refinement; angr for symbolic execution | `.saw`, `.py` (angr scripts) |
| State machine | TLA+ + TLC; trace-refinement comparison | `.tla`, `.cfg` |
| Hardware driver | angr with hardware register model; contracts in markdown | `.py` (angr), `.md` (contracts) |
| Memory operation | angr or KLEE | `.py` |
| Glue / control flow | Reachability and termination only | `.py` (angr) |

## Invocation

`./verify <function_name>` from the repository root dispatches to the correct verifier(s)
based on the function's `@verify` field in its spec block. Examples:

- `@verify: proofs/kiss/kiss_decode_byte.saw` — runs SAW with that script.
- `@verify: proofs/transport/transport_state.tla` — runs TLA+ TLC with that spec.
- `@verify: proofs/uart/uart_init.contracts.md` + corresponding angr script — runs the angr
  script that checks against the contracts.
- `@verify: kat-only` — only KAT (known-answer-test) vectors are required (typical for
  glue/control-flow functions). The reason for this reduced obligation must be stated in a
  comment after the field.

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
