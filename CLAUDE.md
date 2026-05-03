# CLAUDE.md — Operating Instructions

This file is the entry point for any AI agent or human contributor working in this repository.
Read it in full before making any change. It is intentionally durable: it should remain accurate
across the multi-year life of the project. If something here becomes wrong, fix it in the same
commit as the change that made it wrong.

## What this project is

A pure-assembly implementation of the Reticulum Network Stack on the Adafruit ESP32-C6 Feather
(RV32IMAC, single core, 160 MHz, 4 MB flash, 320 KB SRAM). No C, no Rust, no vendor SDK in the
final binary. Every function is hand-written RISC-V assembly with a formal correctness proof
or test-vector validation before it is considered done.

The end goal is a self-contained Reticulum node that can announce, route, link, and exchange
encrypted messages over a real wireless interface (initially LoRa via SPI, eventually the C6's
own WiFi/BLE/802.15.4 radios). The path there is broken into milestones; each milestone is
itself a permanent foundation, not a throwaway demo.

## What this project is NOT

- Not a C or Rust port. Existing C (`microReticulum`) and Rust (`rsReticulum`) ports live
  elsewhere and are reference material only.
- Not a performance optimization of an existing port. We start from the wire format and build up.
- Not a partial port. The scope is exhaustive: every Reticulum function this chip needs to
  perform will be written in asm. The order is what we negotiate; the coverage is non-negotiable.
- Not throwaway. Nothing is built only for one milestone. If a component would be discarded
  later, redesign it now to be permanent.

## Reading order before any work

1. This file, in full.
2. [MASTER_PLAN.md](MASTER_PLAN.md) — vision, scope, milestone roadmap.
3. All ADRs in [docs/adr/](docs/adr/) with status `Accepted`. ADRs are binding.
4. [FUNCTIONS.md](FUNCTIONS.md) — the registry. Find the function you intend to work on.
5. The active milestone spec in [docs/milestones/](docs/milestones/) — find the function's spec entry.
6. Reference material in [references/](references/) for the function's domain (RFC, FIPS pub, upstream Python source).

## Operating principles (binding)

These apply to every change. Violating them is not a tradeoff to debate per-PR; if a principle
needs to change, propose a new ADR and supersede the old one.

1. **One function per file.** No exceptions. File name matches the function name.
2. **Spec before code.** Every `.S` file begins with the machine-readable spec block (see below).
   The spec is written and reviewed before any instructions are written.
3. **Verification before merge.** A function is not done until `./verify <function_name>` returns
   green. Tests alone are not enough for the categories that require formal proof (see ADR-006).
4. **No untracked decisions.** If a choice is non-obvious or contested, write an ADR. Do not
   rely on commit messages or chat logs to preserve rationale.
5. **No dynamic memory.** All state is statically allocated at link time (see ADR-002).
6. **Standard ABI.** Every callable function follows the RISC-V psABI (ILP32) calling convention
   (see ADR-001). No project-internal calling conventions.
7. **Constant-time crypto.** Crypto functions must pass the constant-time verifier. No exceptions.
8. **Update meta-documents in the same commit.** If you add a function, update FUNCTIONS.md.
   If you change a behavior an ADR describes, update the ADR (or supersede it). If you finish
   a milestone, update its spec to `Complete`.
9. **No AI/LLM/Claude attribution in commits.** Commit messages describe the change, not who
   wrote it.
10. **No cross-repo operations.** This repo is self-contained. The sibling repos
    (`rsReticulum`, `Ratspeak`, etc.) are reference material; do not commit to them from here.

## File conventions

### Assembly source files (`src/**/*.S`)

Every `.S` file begins with this block. Fill in every field. The harness parses this block;
malformed blocks fail the build. Per [ADR-0008](docs/adr/0008-naming-toolchain-format.md)
the line prefix is `#` (RISC-V GAS line comment), not `;;` as earlier drafts showed.

```
# ============================================================================
# @function:    <symbol_name>
# @module:      <module name from FUNCTIONS.md, e.g. uart, kiss, sha256>
# @inputs:      <register = description, ...>
# @outputs:     <register or memory location = description, ...>
# @clobbers:    <caller-saved registers modified, comma-separated>
# @preserves:   <callee-saved registers used and restored>
# @stack:       <bytes of stack used; 0 if leaf and no spill>
# @cycles:      <target upper bound; "unbounded" if data-dependent and not ct>
# @ct:          <required | not-required>   (constant-time wrt secret inputs)
# @spec:        <reference to authoritative spec, e.g. fips180-4 §6.2.2>
# @verify:      <comma-separated paths per ADR-0009, e.g. proofs/.../foo.cry, proofs/.../foo.saw, proofs/.../foo.py>
# @verify:      kat-only; <rationale>   (only legal for entry-point glue)
# @tests:       <relative path to test cases, e.g. tests/sha256_compress.py>
# @adrs:        <comma-separated ADR numbers this code implements>
# @status:      <draft | review | tested | verified>
# ============================================================================
```

After the spec block, the file contains exactly one global symbol matching `@function`. Helper
labels are local (prefixed with `.L`). No other global symbols. No data definitions in `.S`
files except read-only constants in `.rodata`; mutable state lives in dedicated `.bss` files
under `src/state/`.

### Documentation files (`docs/**/*.md`)

- ADRs follow the template in [docs/adr/README.md](docs/adr/README.md).
- Milestone specs follow the template in [docs/milestones/README.md](docs/milestones/README.md).
- Use relative links between markdown files. Never hardcode absolute paths.

### Test files (`tests/**/*.py`)

- One test file per function, mirroring `src/` layout.
- Each test file exposes a `verify(target)` entry point callable by the harness.
- No test files import production code (there is no production Python; everything talks to the
  flashed binary via the harness).

## Workflow: adding or completing a function

This is the canonical loop. Follow it for every function.

1. **Pick the function.** Open [FUNCTIONS.md](FUNCTIONS.md), find an entry with status `planned`
   that has no unmet dependencies (its `depends-on` list is all `verified` or empty). If there
   are multiple eligible candidates, prefer the one in the active milestone.
2. **Read the spec.** Find the function's entry in the active milestone spec
   ([docs/milestones/](docs/milestones/)). Read the reference cited in `@spec`. Read any ADRs
   listed in `@adrs`.
3. **Stub the file.** Create `src/<module>/<function>.S` with the full spec block filled in
   and a single `unimp` instruction as the body. Set `@status: draft`. Update FUNCTIONS.md to
   `in-progress`. Commit (subject: `stub <function>`).
4. **Write the test.** Create `tests/<module>/test_<function>.py` with concrete cases: KAT
   vectors, boundary cases, expected error returns. Tests must pass against an oracle (the
   Python reference, the FIPS test vectors, etc.) before any asm is written.
5. **Write the verifier spec.** For functions that require formal verification (see ADR-006),
   create `proofs/<module>/<function>.<ext>` (SAW, Cryptol, TLA+, depending on category).
6. **Implement.** Write the asm. Run `./verify <function>` repeatedly until green. Set
   `@status: tested` once tests pass, `@status: verified` once the formal verifier passes.
7. **Update the registry.** Set the function's status in FUNCTIONS.md. If this function unblocks
   others, note them.
8. **Commit.** Single commit per function once verified, with subject `<function>: <one-line summary>`.
   The diff includes: the asm file, the test file, the verifier spec, and the FUNCTIONS.md update.

## Workflow: updating an ADR

ADRs are immutable once `Accepted`. If circumstances change:

1. Write a new ADR that explicitly supersedes the old one. Use the next available number.
2. In the new ADR, the `Status` line reads `Accepted (supersedes ADR-XXX)`.
3. Edit the old ADR's `Status` line to `Superseded by ADR-YYY` and add a one-line `Supersession reason`.
4. Search the repo for references to the old ADR. Update them to point at the new one.
5. Commit all changes in one atomic commit.

Never rewrite the body of an Accepted ADR. The commit history is a legal record of what was
believed and when.

## Workflow: starting a new milestone

When the active milestone reaches `Complete`:

1. Update the milestone spec's status header to `Complete`. Add a `Retrospective` section noting
   what diverged from the plan and why. Do not edit the rest of the body.
2. Create the next milestone spec in `docs/milestones/milestone-N.md` from the template. Mark
   it `Active`.
3. Update [MASTER_PLAN.md](MASTER_PLAN.md) — change the milestone status in the roadmap table.
4. Update this file's "Currently active milestone" line below.
5. Add planned-state function entries to FUNCTIONS.md for everything the new milestone introduces.

## Currently active milestone

**Milestone 1 — Foundation stack + verifier infrastructure**
(Complete: hardware demo passed on the Adafruit ESP32-C6 Feather
2026-05-02 — boot, KISS framing, packet header parser, and crypto
KAT bridge all verified end-to-end on real silicon over the on-chip
USB-Serial/JTAG endpoint per [ADR-0010](docs/adr/0010-usb-serial-jtag-backend.md)).
See [docs/milestones/milestone-1.md](docs/milestones/milestone-1.md).

**Milestone 2 — Cryptographic primitives** (Complete 2026-05-02:
the full SHA-256 / SHA-512 / HMAC / HKDF / AES-256-CBC / X25519 /
Ed25519 stack is verified Tier A; the production HMAC-DRBG-SHA-256
per NIST SP 800-90A Rev. 1 §10.1.2 is wired over a two-layer entropy
source — deterministic-fake CSPRNG on qemu, on-chip LPPERI hardware
RNG on TARGET_C6 — and discharges the canonical NIST CAVP DRBGVS
COUNT=0 KAT symbolically; Tier B Binsec/Rel constant-time proofs
cover the full AES-256-CBC stack plus representative SHA-256 and
X25519 functions, with the remaining Tier B sweep tracked as a
post-milestone follow-up).
See [docs/milestones/milestone-2.md](docs/milestones/milestone-2.md).

**Milestone 3 — Identity + announce TX** (Active 2026-05-03:
creates Reticulum identity state, destination hash helpers, and a
signed HEADER_1 announce TX path over the existing KISS serial
development interface).
See [docs/milestones/milestone-3.md](docs/milestones/milestone-3.md).

Update this section whenever a milestone becomes active or completes.

## Toolchain assumptions

Toolchain versions and install instructions live in [toolchain/README.md](toolchain/README.md).
The short version (per [ADR-0008](docs/adr/0008-naming-toolchain-format.md)): vanilla
`riscv64-elf-binutils` (`as` and `ld` only — no compiler) targeting RV32IMAC via
`-march=rv32imac -mabi=ilp32`, `esptool.py` for flashing, `qemu-system-riscv32` for emulation,
Python 3.11+ for the harness.
Do not pin specific versions in this file; pin in `toolchain/versions.lock` so the lock can move
without churning every doc.

## Verification tools

See ADR-0006 for the policy and [ADR-0009](docs/adr/0009-verifier-toolchain.md)
for the concrete tool stack: Cryptol 3.5.0 + SAW 1.5 (Tier A algorithmic),
Binsec 0.11.1 (Tier B constant-time on RV32), angr 9.2.213 + pypcode 3.3.3
(Tier C binary equivalence on RV32IMC), TLA+ Tools 2.19 (Tier D state
machines), Sail 0.20.1 + the official sail-riscv model (Tier E ISA reference).

Tooling and per-tier mappings live in [proofs/README.md](proofs/README.md).
The single command an agent needs to run is `./verify <function_name>`, which
dispatches to **every** verifier listed in the function's comma-separated
`@verify` field (e.g., `proofs/.../foo.cry, proofs/.../foo.saw, proofs/.../foo.py`).
All must pass for `@status: verified`. The directory was renamed from `verify/`
to free that name for the dispatcher script — see
[ADR-0008](docs/adr/0008-naming-toolchain-format.md).

Verifier binaries live under `toolchain/local/bin/` (project-local symlinks
into `~/opt/galois/`, `~/.opam/binsec/`, `~/.ghcup/`, etc.) and the dispatcher
prepends that directory to `PATH` for proof scripts; Python verifiers run
under `toolchain/venv/bin/python` so `angr` is importable. No shell dotfile
changes required.

## Escalation: when to ask the user

Do not silently change scope or revisit accepted ADRs. Ask the user (in the calling session)
when:

- A function's spec is ambiguous or contradicts another spec.
- A milestone's plan is no longer reachable as written and needs revision.
- An accepted ADR appears to need supersession.
- A toolchain change would force a version bump that affects existing verified functions.
- Hardware behavior diverges from documented behavior in a way that suggests an erratum.

For routine work (writing asm to a clear spec, fixing a failing test, updating FUNCTIONS.md
status), do not ask — just do it and commit.

## Things to never do

- Never call C or Rust code. The final binary is asm only.
- Never use the vendor SDK in production code. Reference its source for hardware register
  semantics, then write the asm yourself.
- Never use dynamic memory allocation. All state is link-time static.
- Never introduce a function without updating FUNCTIONS.md in the same commit.
- Never mark a function `verified` without the formal verifier passing for its category.
- Never edit an Accepted ADR's body. Supersede it instead.
- Never mention AI, LLM, or Claude in commit messages or code comments.
- Never push to a remote (this repo is local-only by policy; if a remote is added, it requires
  a new ADR).
- Never delete or rewrite git history.

## Maintenance of this file

This file is the longest-lived document in the repo. When you change anything that affects:

- The reading order (a new top-level doc is added)
- The workflow (a new step is required, an existing step changes)
- The principles (an ADR changes the rules)
- The active milestone

...update this file in the same commit. If a section becomes wrong and you do not have time
to fix it, mark it with `> TODO: outdated, see <reason>` rather than leaving silently-wrong
text. A wrong instruction is worse than a missing one.
