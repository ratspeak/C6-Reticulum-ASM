# ADR-0006: Per-function formal verification, tooling per category

- **Status:** Accepted (partially superseded by [ADR-0008](0008-naming-toolchain-format.md) — directory `verify/` renamed to `proofs/`; references to `references/` and `verify/` directory paths in this body should be read as `proofs/`)
- **Date:** 2026-05-01

## Context

The user-stated goal of this project includes mathematical certainty of correctness before
moving on from each stage. This is achievable for an asm project — RISC-V has a ratified
formal ISA specification (Sail), instruction semantics are deterministic, and there is no
undefined behavior to reason around. The tooling is mature enough to be production usable;
HACL\*, Vale, fiat-crypto, s2n-bignum, and CompCert all ship verified code in production.

The question is not "can we?" but "how do we apply formal methods consistently across a
multi-year project with hundreds of functions, each with different verification needs?"

A naive answer ("verify everything with one tool") fails because:

- Crypto needs equivalence proofs against mathematical specifications and constant-time
  proofs against side channels. SAW + Cryptol or fiat-crypto are the right tools.
- Protocol state machines need refinement proofs against an abstract specification. TLA+ is
  the standard tool.
- Hardware drivers need pre/post register-state contracts and reachability analysis.
  Symbolic execution (angr, KLEE) is the right tool.
- Pure data transformations (parsers, framers) need exhaustive input-space analysis or
  refinement proofs. SAW or symbolic execution, depending.

A different verification tool per category is the only honest answer.

## Decision

Every function in the production binary has a verification obligation that depends on its
category. The obligation is described in the function's `@verify` field and enforced by
`./verify` (per ADR-0005). Functions are not marked `verified` in FUNCTIONS.md until their
obligation is discharged.

The categories and their verification tools:

| Category | Examples | Verification obligation | Primary tool(s) |
|----------|----------|-------------------------|-----------------|
| **Crypto primitive** | SHA-256 compression, AES round, Curve25519 field op, X25519 scalar mult | (a) Equivalence to reference spec, (b) constant-time wrt secret inputs, (c) KAT vectors pass | fiat-crypto for field arithmetic, SAW + Cryptol for primitives, ct-verif or Binsec/Rel for constant-time, NIST/RFC test vectors |
| **Pure data transformation** | KISS encode/decode, packet header parser, hex formatter | Refinement proof against reference spec OR exhaustive symbolic execution on bounded input space | SAW for refinement; angr or KLEE for symbolic execution |
| **State machine** | Announce TX state, link establishment state, transport routing state | TLA+ specification + trace refinement proof: every observable trace from the asm matches a trace of the TLA+ spec | TLA+ TLC model checker; trace logger emits structured events the harness compares to TLA+ generated traces |
| **Hardware driver** | UART driver, SPI driver, flash driver, GPIO control | Pre/post contracts on hardware register state; symbolic execution of all paths; bounded-time reachability for IRQ handlers | angr against a hardware model derived from the C6 TRM; contracts encoded in `@verify` directives |
| **Memory operation** | Bounded copy, ring buffer push/pop, pool claim/release | Bounds proven via symbolic execution; no out-of-bounds access on any path | angr or KLEE |
| **Glue / control flow** | `main`, ISR dispatcher, scheduler tick | Reachability and termination only; no functional contract beyond the dispatch table | angr; for `main`, model checking of the top-level event loop in TLA+ |

Additional rules:

1. **Constant-time is not optional for crypto.** A crypto function that fails the constant-time
   verifier may not be merged, regardless of whether its KAT vectors pass.
2. **Reference specs are vendored.** `references/` contains the FIPS pubs, RFCs, Curve25519
   paper, RISC-V ISA spec, Sail model, and the upstream Python Reticulum source pinned to
   a specific commit. These are the ground truth our verifiers reference.
3. **Verification effort cap per function.** If a single function's verification has not
   discharged after 3 months of focused effort, escalate to the user for re-scoping rather
   than dropping the requirement. Possible re-scopings: split the function, change algorithm,
   accept reduced obligation (KAT-only with documented rationale), defer to a future ADR.
4. **Verifier failures must be specific.** `./verify` reports which obligation failed
   (KAT, equivalence, constant-time, contract) so an agent can act on the failure.
5. **Verifier specs are versioned with the code.** When a function changes, its verifier
   must re-pass; if the verifier itself needs updating, that is part of the same commit.

## Consequences

### Positive

- The user-stated goal of mathematical certainty per stage is achievable and operationalized
  per function.
- Bugs discovered post-verification are extremely rare; the failure modes shift from "wrong
  output" to "verifier missed a property" or "spec was incorrect," both of which are easier
  to fix correctly.
- AI-agent contributions become trustworthy: an agent's PR is correct iff `./verify` passes,
  and the verifier is far harder to fool than tests alone.
- We inherit the precedent and tooling of HACL\*, Vale, fiat-crypto, etc. We are not
  inventing verified-asm methodology; we are applying it.

### Negative

- Per-function effort grows by an estimated 30–50% versus tested-only code. Crypto primitives
  are the worst case (potentially 3–5×).
- The toolchain is large: fiat-crypto, SAW, Cryptol, angr/KLEE, ct-verif, TLA+, Sail.
  Initial setup is substantial; the harness must abstract this so individual contributors
  do not have to learn every tool to verify a single function.
- Some functions will be intractable to fully verify and will require the escalation path.
  Documenting these honestly (with the reduced obligation in their `@verify` field and a
  rationale ADR) is mandatory.

### Neutral

- The verifier setup work is concentrated in milestone 1 (the harness) and milestone 2
  (crypto, the most demanding category). Subsequent milestones reuse the established
  pipelines.

## Alternatives considered

**Tests only, no formal verification.** Reject. This is what the project explicitly is not.
The user has called out mathematical certainty as a foundational requirement.

**Formal verification only for crypto.** Reject. State machines and hardware drivers are
where the most subtle Reticulum bugs live; verifying only crypto leaves the majority of
the codebase under the same regime as a typical untested project.

**One unified verifier (e.g., everything in Coq).** Reject. Single-tool ambitions in formal
methods produce paralysis. Each tool is best-of-breed for its category; the integration
cost (a uniform `./verify` interface) is small compared to the cost of trying to make one
tool do all jobs.

## References

- [HACL\*](https://github.com/hacl-star/hacl-star) — verified crypto library, precedent for
  per-primitive verification.
- [Vale](https://github.com/project-everest/vale) — DSL for verified assembly crypto.
- [fiat-crypto](https://github.com/mit-plv/fiat-crypto) — generates verified field
  arithmetic for elliptic curves.
- [SAW (Software Analysis Workbench)](https://saw.galois.com/) — equivalence and refinement
  proofs.
- [Cryptol](https://cryptol.net/) — high-level spec language SAW consumes.
- [TLA+](https://lamport.azurewebsites.net/tla/tla.html) — temporal-logic state-machine
  specification.
- [angr](https://angr.io/) and [KLEE](https://klee.github.io/) — symbolic execution.
- [ct-verif](https://github.com/imdea-software/verifying-constant-time) — constant-time
  verification.
- [Binsec/Rel](https://binsec.github.io/) — relational symbolic execution for constant-time.
- [Sail](https://github.com/rems-project/sail) — official RISC-V ISA formal model.
- ADR-0005 — test harness, the dispatch layer for verifiers.
- ADR-0007 — project structure, including the `@verify` field in function spec blocks.
