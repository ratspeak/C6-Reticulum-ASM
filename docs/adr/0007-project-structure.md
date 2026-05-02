# ADR-0007: One-function-per-file with machine-readable specs

- **Status:** Accepted
- **Date:** 2026-05-01

## Context

This project is designed for incremental contribution by AI agents over a multi-year span,
with formal verification per function. Both of those properties depend on the codebase being
*decomposable* into units small enough that an agent can complete and verify a unit in one
focused turn, and *self-describing* enough that an agent reading a file in two years can
understand its role without conversation context.

A single large `.S` file with hundreds of functions and shared internal state would be
incompatible with both properties. So would loosely-organized files where the contract of
each function is implicit in the code rather than declared explicitly.

## Decision

The project uses a one-function-per-file structure with a mandatory machine-readable spec
block at the top of every assembly source file. Specifically:

### File organization

- **`src/<module>/<function_name>.S`** contains exactly one global symbol named
  `<function_name>`. Helper labels are local (prefixed `.L`).
- **`src/state/<module>.S`** contains the `.bss` and `.data` declarations for that module's
  state (per ADR-0002). State is co-located by module, not by function.
- **`src/include/`** contains shared constants (`config.S`, `regs.S`, `errno.S`, etc.)
  consumed via assembler `.include` directives. No code; only equates.
- **`tests/<module>/test_<function_name>.py`** contains the harness-callable test for that
  function (per ADR-0005).
- **`verify/<module>/<function_name>.<ext>`** contains the formal verification spec — extension
  varies by tool: `.saw`, `.cry`, `.tla`, `.smt2`, etc. (per ADR-0006).

Module names are short, lowercase, dependency-ordered: `boot`, `clock`, `uart`, `log`, `kiss`,
`packet`, `crypto/sha256`, `crypto/aes`, `crypto/x25519`, `identity`, `transport`, `link`,
`resource`, `interface/lora`, etc.

### Mandatory spec block

Every `.S` file begins with this block. Fields are mandatory; the harness parser fails the
build if any field is missing or malformed.

```
;; ============================================================================
;; @function:    <symbol_name>
;; @module:      <module name>
;; @inputs:      <register = description, ...>
;; @outputs:     <register or named memory location = description, ...>
;; @clobbers:    <caller-saved registers used, comma-separated>
;; @preserves:   <callee-saved registers used and restored>
;; @stack:       <bytes; integer; 0 if leaf with no spill>
;; @cycles:      <integer upper bound; "unbounded" requires @ct: not-required>
;; @ct:          <required | not-required>
;; @spec:        <reference to authoritative spec>
;; @verify:      <relative path to verifier spec OR "kat-only" with rationale>
;; @tests:       <relative path to test file>
;; @adrs:        <comma-separated ADR numbers this code implements>
;; @status:      <draft | review | tested | verified>
;; ============================================================================
```

The block is parsed by `tools/parse_spec.py` (introduced in milestone 1). Static checks
that run on every commit:

- All fields present.
- Referenced files (`@verify`, `@tests`) exist.
- Referenced ADRs exist and are `Accepted`.
- `@status: verified` requires `./verify <function_name>` to currently pass.
- The asm body uses only registers declared in `@inputs`, `@outputs`, `@clobbers`, `@preserves`
  (verified by an asm-level static analyzer that runs in CI).
- `@cycles: unbounded` is permitted only if `@ct: not-required`. Constant-time functions must
  have a bounded cycle count.

### Function registry

[FUNCTIONS.md](../../FUNCTIONS.md) is the single source of truth for the existence and status
of every function. Every entry contains: name, module, status, dependencies, ADR refs, brief
description, and links to source/tests/verifier. The CLAUDE.md workflow requires every function-
introducing commit to update FUNCTIONS.md atomically.

### Why "one function per file"

- Agents work on one function per turn. File-level locality matches the unit of agentic work.
- `git log src/<module>/<function>.S` shows the complete history of one function — useful for
  debugging "when did this regress" without noise from neighboring functions.
- Code review is per-function: a PR that touches three functions touches three files. The
  diff is unambiguous about scope.
- The spec block at the top of each file is read every time a contributor opens it. The
  contract is impossible to forget or misremember.

## Consequences

### Positive

- The agentic workflow described in CLAUDE.md works mechanically: pick a function, open one
  file, write to one spec, verify with one command.
- Code review effort scales with function count, not file count. PRs are small and focused.
- The spec block makes reverse-engineering a function's intent unnecessary. The function's
  inputs, outputs, side effects, ABI usage, and verification status are right there.
- Static analysis catches a large class of contract violations (undeclared register use,
  missing tests, stale ADR references) before they reach review.
- Refactoring at the file level is safe: moving a function moves one file.

### Negative

- File count is large. A complete project will have hundreds of `.S` files. This is a tooling
  consideration (file-tree navigation needs to be good) but not a correctness consideration.
- Some helper code that would naturally be inline within a larger file becomes a separate
  small function, with the overhead of a call. We accept the cost; on RV32IMAC, function
  call overhead is small (3–5 cycles for the call+return), and the structural clarity is
  worth it. Performance-critical inner loops can be inlined manually within their parent
  function as `.L`-labeled blocks.
- The spec block adds ~15 lines of comment to every file. Worth it.

### Neutral

- The static analyzer that enforces the spec block contract is itself a Python tool living
  in `tools/`. It must be maintained; its tests live in `tests/tools/`.

## Alternatives considered

**Module-per-file (multiple functions per file).** Reject. Would re-introduce the
implicit-contract problem the spec block solves, and would make per-function code review
harder.

**Spec block in a separate file (e.g., `<function>.spec.yaml`).** Reject. The spec belongs
adjacent to the code; splitting them invites drift. The asm-comment format keeps them in
the same file and the same diff.

**No spec block, just consistent naming and documentation conventions.** Reject. Conventions
that are not machine-checkable rot. The spec block is enforced by the parser.

## References

- ADR-0001 — calling convention, which the spec block's `@inputs`/`@outputs`/`@clobbers`/
  `@preserves` fields encode.
- ADR-0002 — memory model, which the per-module state file structure implements.
- ADR-0005 — test harness, which the `@tests` field links to.
- ADR-0006 — formal verification, which the `@verify` field links to.
- CLAUDE.md — the workflow that depends on this structure.
