# ADR-0009: Verifier toolchain — Cryptol/SAW + Binsec/Rel + angr+pcode + Sail-RISCV

- **Status:** Accepted
- **Date:** 2026-05-02
- **Refines:** ADR-0006 (per-function formal verification, tooling per category)

## Context

ADR-0006 named the right *kinds* of tools per category (SAW + Cryptol for crypto,
ct-verif or Binsec/Rel for constant-time, angr/KLEE for symbolic execution, TLA+
for state machines, etc.) but stopped short of pinning specific binaries, settling
the algorithm-vs-binary distinction, or accounting for what is actually deployable
on a pure-RV32 asm project today.

Three concrete realities shaped this ADR:

1. **SAW does not verify RV32 binaries directly.** SAW 1.5 ships LLVM, MIR, JVM,
   and x86 (via `macaw-x86`) frontends only. The Galois `macaw` monorepo contains
   `macaw-riscv`, `macaw-riscv-symbolic`, `macaw-riscv-syntax`, and
   `macaw-loader-riscv` packages, but `saw-script` has not yet exposed an
   `llvm_verify_riscv` builtin analogous to `llvm_verify_x86`. Closing that gap
   is a multi-month Haskell contribution upstream, not a "build with a flag" job.
2. **`ct-verif` is x86-only.** ADR-0006's mention of `ct-verif` cannot be honored
   on RV32. `Binsec/Rel` (the relational engine inside `binsec` 0.11.1) does
   support `-isa riscv32` as a first-class target with `-checkct`.
3. **angr's stock VEX backend has no RV32 lifter, but its pcode engine
   does.** Via `pypcode` 3.3.x and Ghidra's lifter, angr can symbolically
   execute `RISCV:LE:32:RV32IMC` (and the IMAC/GC variants) directly on our
   built ELF.

The decision is therefore three-fold: pin specific tools, define a layered
verification model that names each tool's responsibility, and lay the path
forward for full SAW-on-RV32 equivalence proofs.

## Decision

Every function verified under this project is verified through some subset of
the following five tiers. Each tier is discharged by a specific tool. The set
of tiers required for a given function depends on its category (per ADR-0006)
and is encoded in its `@verify` field as a comma-separated list of paths to
verifier scripts.

### Tier A — Algorithmic specification (Cryptol + SAW)

- **Tool:** Cryptol 3.5.0 + SAW 1.5 (Galois prebuilts, arm64-darwin
  with-solvers).
- **Artifact:** `proofs/<module>/<function>.cry` (Cryptol module) and
  `proofs/<module>/<function>.saw` (SAW driver).
- **What it proves:** Our Cryptol model of the algorithm is algebraically
  consistent with its standard (FIPS, RFC, IETF). For composite primitives
  (e.g., `aes256_encrypt_block`), it proves that our top-level Cryptol model
  composes correctly from the Cryptol models of its sub-primitives.
- **Required for:** every crypto primitive (`@module: crypto/*`).

### Tier B — Constant-time (Binsec/Rel)

- **Tool:** Binsec 0.11.1 (`-isa riscv32 -checkct`), with relational symbolic
  execution (`-checkct-no-relse=false`).
- **Artifact:** `proofs/<module>/<function>.bsc` driver pointing at the
  function's address in the firmware ELF and listing secret-tagged inputs.
- **What it proves:** No control-flow branch and no memory-access address
  depends on a secret-tagged input, on every reachable execution path.
- **Required for:** every function with `@ct: required`.

### Tier C — Binary equivalence (angr + pypcode RV32IMC)

- **Tool:** angr 9.2.213 with `archinfo.ArchPcode("RISCV:LE:32:RV32IMC")` and
  `engine=angr.engines.UberEnginePcode`.
- **Artifact:** `proofs/<module>/<function>.py` script that loads the firmware
  ELF, symbolically executes the function from its symbol address with
  controlled inputs and a callee-saved register snapshot, and asserts (a) the
  post-state of memory matches the Cryptol spec's predicted bytes, (b) callee-
  saved registers are preserved, (c) no writes occur outside the documented
  output regions, and (d) the function returns within a bounded number of
  basic blocks.
- **What it proves:** The RV32IMC binary computes the function described by
  the Cryptol spec, on the symbolic input domain explored by angr.
- **Required for:** every crypto primitive, every pure data transformation,
  every memory operation, every glue/control-flow function.
- **Limitation:** angr's symbolic exploration is bounded and not exhaustive;
  it discovers all paths reachable within the basic-block budget but may miss
  behavior on inputs requiring deeper exploration. Tier C is a strong
  supplement to KAT, but it is not a full equivalence proof in the SAW sense.

### Tier C-future — SAW + macaw-riscv (full equivalence proof)

- **Path forward:** GHC 9.6.7 and cabal 3.10.3.0 are installed via ghcup and
  symlinked into `toolchain/local/bin/`. The macaw monorepo is buildable
  against this toolchain. Closing the gap requires:
  1. Building `macaw-riscv-symbolic` against the GHC version SAW uses.
  2. Adding an `llvm_verify_riscv` (or equivalent) builtin to a forked
     `saw-script`, mirroring the structure of `crucible_llvm_verify_x86`.
  3. Upstreaming the contribution to GaloisInc/saw-script.
- **When pursued:** when the project has at least one composite crypto
  primitive (e.g., `aes256_encrypt_block`) where Tier C's bounded angr
  exploration is no longer sufficient confidence, and the ROI of the
  contribution to SAW upstream exceeds the cost.
- **Until then:** Tier C (angr) remains the binary-equivalence layer, and
  every crypto primitive carries an explicit note in its spec block that
  Tier C is bounded-exploration, not full equivalence.

### Tier D — State machines (TLA+ / TLC)

- **Tool:** TLA+ Tools 2.19 (tla2tools.jar via `tlc` wrapper).
- **Artifact:** `proofs/<module>/<function>.tla` + optional `.cfg`.
- **What it proves:** The state machine described in TLA+ refines the
  observable trace of the asm, and satisfies its safety/liveness properties.
- **Required for:** every state-machine function (transport, link, resource
  layers — milestone 5+).

### Tier E — ISA ground truth (Sail-RISCV, reference only)

- **Tool:** Sail 0.20.1 (compiler) + the official `riscv/sail-riscv` model
  vendored under `references/sail-riscv/` at commit `4d5530b`.
- **What it provides:** The authoritative formal RV32 semantics. Used to
  validate the lifter behavior of angr's pcode engine and Binsec's RV32
  frontend when discrepancies arise. Not run per-PR.
- **Required for:** none directly; consulted when debugging a Tier B/C/C-future
  result that conflicts with KAT.

### `@verify` field syntax (extends ADR-0007)

The `@verify` field in a function's spec block is one of:

- `kat-only; <rationale>` — KAT vectors are the only obligation. Permitted
  only for entry-point glue and functions whose only behavior is dispatch.
- `<path>` (single backend) — e.g., `proofs/crypto/sha256/sha256_init.py`.
- `<path1>, <path2>, ...` — multi-tier verification. Every listed verifier
  must pass for `@status: verified`.

`./verify <function>` parses the comma-separated list and dispatches each
backend by file suffix:

| Suffix | Backend | Tier |
|--------|---------|------|
| `.cry` | `cryptol -c ":l <path>"` (typecheck only) | A |
| `.saw` | `saw <path>` (Cryptol-Cryptol equivalence) | A |
| `.py` | `toolchain/venv/bin/python <path>` (angr) | C |
| `.bsc` | `binsec -config <path>` (Binsec/Rel) | B |
| `.tla` / `.cfg` | `tlc <path>` | D |
| `.md` | not-implemented (contracts-only documentation) | — |

All proof scripts run with `toolchain/local/bin` prepended to `PATH` so the
project-local `saw`, `cryptol`, `binsec`, `sail`, and `tlc` are found without
shell dotfile changes. Python verifiers run under `toolchain/venv/bin/python`
so `angr` is importable.

### Toolchain layout

The project's verifier binaries live in user-scope locations and are
symlinked into `toolchain/local/bin/`. The lock file (`toolchain/versions.lock`)
pins exact versions. New verifier installations belong in the same scheme
and must be reflected in the lock file in the same commit.

```
~/opt/galois/                 SAW + Cryptol prebuilts (extracted tarballs)
~/opt/tlaplus/tla2tools.jar   TLA+ Tools jar
~/.ghcup/                     GHC + cabal (via ghcup --no-setup)
~/.opam/binsec/               opam switch hosting binsec, sail, coq
toolchain/local/bin/          symlinks + wrapper scripts (PATH-friendly)
toolchain/venv/               Python venv with angr, claripy, archinfo, pypcode
references/sail-riscv/        official RV32 ISA model (read-only)
references/fiat-crypto/       verified field arithmetic source (read-only)
```

## Consequences

### Positive

- ADR-0006's ambition is operationalized end-to-end. Every tool named there
  is now installed, named, and integrated with `./verify`.
- The verifier stack covers the four meaningful tiers (algorithmic spec,
  constant-time, binary equivalence, state machine) on RV32 today, without
  blocking on upstream tooling work.
- The Tier C-future path is documented and physically possible (GHC + cabal
  installed) — we can pursue full SAW-on-RV32 equivalence whenever the ROI
  flips, without re-litigating the toolchain.
- The `@verify` syntax composes: a function can carry just `.py` (memory
  ops), or `.cry,.saw,.py` (most crypto), or `.cry,.saw,.py,.bsc` (secret-
  handling crypto), without changing the spec-block format.
- Project-local `toolchain/local/bin/` plus the venv mean the verification
  stack is reproducible from this repo without polluting the user's shell.

### Negative

- The toolchain is heavy. Total disk footprint is ~3 GB (SAW with-solvers
  alone is 800 MB extracted). First-time setup is real engineering work, not
  `pip install`.
- Tier C (angr) is bounded symbolic exploration, not full equivalence. Until
  Tier C-future ships, our binary-level guarantee for crypto is stronger than
  KAT-only but weaker than SAW would deliver. Spec blocks must be honest
  about this distinction.
- The pcode engine in angr is less battle-tested than its VEX engine; we may
  encounter lifter bugs that require either cross-validation against Sail or
  a workaround. Sail is intentionally available for exactly this case.
- Binsec/Rel's RV32 frontend is younger than its x86 frontend. Same risk
  mitigation as angr: cross-check against Sail when a `-checkct` result
  surprises us.

### Neutral

- The verifier setup work is concentrated in this commit and is amortized over
  the entire project lifetime. Subsequent functions reuse the same wiring;
  the cost-per-function is the time to write `.cry` + `.saw` + `.py` + (if
  secret-handling) `.bsc`.

## Alternatives considered

**Wait for upstream `llvm_verify_riscv` in saw-script.** Reject. The Galois
team's roadmap does not include this within the project's timeline. Waiting
means either no formal verification or a Tier C alternative anyway; we'd be
making the same decision as today, but later.

**Build `llvm_verify_riscv` ourselves now and skip Tier C (angr).** Reject for
this commit, accept as Tier C-future. The estimated effort is multi-month
Haskell research work; it is the wrong opening move when angr provides a
working binary-equivalence layer in days. Pursue once we have a function
where angr's bounded exploration is the limiting factor.

**Rely on KAT + hand audit only.** Reject. ADR-0006 forbids this for crypto
and state machines, and the project's stated goal is mathematical certainty.
Hand audits do not survive multi-year codebases without compounding error.

**Use a single tool stack (e.g., everything via Coq / Lean + Sail).** Reject.
Best-of-breed-per-category was chosen in ADR-0006 and that judgment stands.
Single-tool ambitions in formal methods produce paralysis or tool-shaped
designs.

**Treat Tier A (Cryptol/SAW algorithmic) as optional, since Tier C catches
binary mistakes.** Reject. Tier A catches *spec* mistakes — incorrect FIPS
transcription, wrong byte orders, off-by-one constants. Tier C cannot catch
a wrong spec because Tier C's oracle *is* the spec. Both are required.

## References

- [ADR-0006](0006-formal-verification.md) — the categorisation this ADR refines.
- [ADR-0005](0005-test-harness.md) — the `./verify` dispatcher this ADR extends
  to multi-backend.
- [ADR-0007](0007-project-structure.md) — the spec-block format whose `@verify`
  field this ADR extends to comma-separated paths.
- [ADR-0008](0008-naming-toolchain-format.md) — the upstream toolchain pinning
  policy this ADR follows for verifier tools.
- [SAW 1.5 release](https://github.com/GaloisInc/saw-script/releases/tag/v1.5).
- [Cryptol 3.5.0 release](https://github.com/GaloisInc/cryptol/releases/tag/3.5.0).
- [macaw monorepo](https://github.com/GaloisInc/macaw) — Tier C-future path.
- [Binsec 0.11.1](https://github.com/binsec/binsec) — Binsec/Rel constant-time engine.
- [angr](https://angr.io/) + [pypcode](https://github.com/angr/pypcode) — Ghidra
  RV32IMC lifter.
- [Sail-RISCV](https://github.com/riscv/sail-riscv) — official ISA semantics.
- [fiat-crypto](https://github.com/mit-plv/fiat-crypto) — verified field arithmetic
  oracle (X25519 milestone 2).
- [TLA+ Tools](https://github.com/tlaplus/tlaplus).
- [HACL\*](https://github.com/hacl-star/hacl-star) and
  [Vale](https://github.com/project-everest/vale) — precedent for the layered
  algorithmic-spec + binary-equivalence approach in production crypto.
