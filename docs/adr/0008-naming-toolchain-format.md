# ADR-0008: Verifier directory rename, vanilla binutils, hex log timestamps, `#` comment prefix

- **Status:** Accepted
- **Date:** 2026-05-01
- **Supersedes (in part):** ADR-0006 §References to `verify/`; ADR-0007 §File
  organization (`verify/` path) and §Mandatory spec block (`;;` comment
  prefix); the `riscv32-esp-elf-*` pin in
  [toolchain/README.md](../../toolchain/README.md); the example log
  formatting in [ADR-0004](0004-diagnostics.md).

## Context

Three small but binding decisions surfaced during milestone-1 bring-up. None
warrants its own ADR; bundling them into one keeps the lifecycle bookkeeping
tractable.

1. **`verify/` directory and `./verify` command collide.** ADR-0005 and the
   milestone-1 spec describe `./verify <function>` as the user-facing
   dispatcher. ADR-0007 places per-function verifier specs at
   `verify/<module>/<function>.<ext>`. A POSIX filesystem cannot host both an
   executable file `verify` and a directory named `verify/` in the same
   parent. The mismatch existed in the initial-commit spec set and was not
   noticed until tooling was wired.

2. **Toolchain assembler.** The toolchain README pinned
   `riscv32-esp-elf-as` (Espressif's crosstool-NG fork). It is not packaged
   in homebrew and would require manual install of an Espressif distribution
   for every contributor. Vanilla `riscv64-elf-binutils` is one
   `brew install` away and can target RV32IMAC via `-march=rv32imac
   -mabi=ilp32`. We hand-write the linker script anyway (ADR-0002), so the
   Espressif fork's pre-configured ESP image-header support is not
   load-bearing — we re-derive that ourselves either way.

3. **Log timestamp encoding.** ADR-0004's example `00012345\tkiss\trx_frame…`
   does not say whether the leading 8-character timestamp is hex or decimal.
   Both interpretations are coherent; we have to pick one to commit asm and
   parser to.

4. **Spec-block comment prefix.** ADR-0007 and CLAUDE.md show the per-line
   spec block prefixed with `;;`. RISC-V GAS does not treat `;` or `;;` as
   a comment character — `;` is a statement separator, so `;; @function:`
   parses as two empty statements followed by a syntax error. The first
   `make build` attempt fails the assembler with "junk at end of line" on
   every spec-block line. We have to pick a prefix the assembler tolerates.

## Decision

### 1. Rename `verify/` → `proofs/`.

The directory holding formal-verification specs is renamed to `proofs/`. The
content is unchanged. References in CLAUDE.md, ADR-0006, ADR-0007,
milestone-1.md, and the README files are updated in the same commit as the
rename. The freed name is taken by an executable wrapper `./verify` at the
repo root, which forwards to `tests/harness/verify.py` (the dispatcher).

### 2. Adopt vanilla `riscv64-elf-binutils` for assembly + linking.

The toolchain pin moves from `riscv32-esp-elf-as / -ld` to `riscv64-elf-as /
-ld` (the homebrew package), targeting RV32IMAC via `-march=rv32imac
-mabi=ilp32`. `versions.lock` and `toolchain/README.md` are updated to
match. The Espressif fork is preserved as a fallback (a contributor can
substitute it in `toolchain/versions.lock`); CI uses vanilla binutils.

The Espressif boot ROM image header is independent of the assembler choice;
we still document it in `docs/hardware/image-header.md` and produce it
ourselves at link time.

### 3. Log timestamps are 8 hex digits (zero-padded).

The asm `log_event` primitive emits the millisecond-since-boot timestamp as
8 hex digits, produced by a single `log_hex(width=8)` call. The harness
parser (`tests/harness/log_parser.py`) interprets `ts_raw` as base-16 and
exposes `LogEvent.ts_ms` accordingly. Decimal would have required a
divide-and-modulo formatter in the asm; hex is one shift-and-mask per nibble.

The example in ADR-0004 (`00012345\tkiss\trx_frame…`) is therefore
`0x12345 ms` ≈ 74.5 s of uptime, not 12,345 ms.

### 4. Spec-block lines are prefixed with `#`, not `;;`.

Every per-line entry in the ADR-0007 spec block uses `#` as its prefix
(GAS's standard line-comment character on RISC-V). The fence lines, which
were `;; ===…===` in the ADR-0007 template, become `# ===…===`. Block
comments (`/* … */`) are reserved for free-form rationale below the spec
block. `tools/parse_spec.py` accepts `#`-prefixed blocks; the templates in
CLAUDE.md and ADR-0007 should be read as if `;;` were `#`.

Example (the new canonical form):

```
# ============================================================================
# @function:    sha256_compress
# @module:      crypto/sha256
# ...
# ============================================================================
```

## Consequences

### Positive

- `./verify <function>` works as documented in ADR-0005 and CLAUDE.md.
- New contributors install the toolchain with two homebrew packages
  (`riscv64-elf-binutils`, `qemu`) instead of hunting down an Espressif
  crosstool-NG release.
- The asm `log_event` is one primitive simpler (no decimal divide path on
  the hot logging path).
- All three decisions removed ambiguities that would have produced silent
  divergence between asm, parser, and verifier specs.

### Negative

- A grep for the literal `verify/` in older external notes or chat logs
  will not match the current directory name. Anyone returning after a
  break must read this ADR.
- We give up the marginal convenience of Espressif's `riscv32-esp-elf`
  build's pre-configured linker scripts. We were going to hand-write the
  linker script anyway, so the loss is small.
- The asm `log_hex(width=8)` formatter is locked in; switching to decimal
  later would be a wire-format change requiring all log consumers to
  update. We accept the lock-in.

### Neutral

- The directory rename is a `git mv`; history follows the files.
- Both the Espressif fork and vanilla binutils accept the same `.S` source
  syntax for RV32IMAC, so existing or future asm files do not need
  per-toolchain conditionals.

## Alternatives considered

**Keep `verify/` and call the dispatcher `./vrfy` or `./run-verify`.**
Reject. The documented invocation is `./verify`; honoring it is worth a
seven-character directory rename.

**Ship a `Makefile`-only interface (`make verify FN=…`) and never expose
`./verify`.** Reject. The agent-friendly interface in ADR-0005 specifically
calls out `./verify <function>` as the single command. Make targets are
fine as a parallel ergonomic, but the principal invocation should match
the ADR.

**Stay on the Espressif fork via manual install instructions.** Reject.
Adds a per-contributor friction (download a tarball, set PATH) for no
verification benefit.

**Decimal log timestamps.** Reject. Requires a div/mod loop in asm for
every `log_event` call; no readability win over hex once contributors are
familiar with the format.

**Block comments (`/* … */`) for the whole spec block.** Reject. Per-line
prefixes are easier for tooling to parse line-by-line, easier to diff
review, and survive copy-paste better than nested-comment hazards. We
keep `/* … */` for free-form rationale only.

## References

- [ADR-0004](0004-diagnostics.md) — log format whose timestamp this ADR
  pins.
- [ADR-0005](0005-test-harness.md) — `./verify <function>` invocation
  contract.
- [ADR-0006](0006-formal-verification.md) — verifier spec locations
  (renamed directory).
- [ADR-0007](0007-project-structure.md) — file organization including the
  per-function verifier spec path.
- [docs/open-questions.md](../open-questions.md) — the OQ-1, OQ-2, OQ-3
  entries this ADR resolves; the file is updated to mark them resolved.
- [toolchain/README.md](../../toolchain/README.md) — toolchain pin.
- [toolchain/versions.lock](../../toolchain/versions.lock) — pinned
  versions.
