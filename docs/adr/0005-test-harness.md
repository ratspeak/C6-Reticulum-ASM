# ADR-0005: Mandatory host-side test harness from day 1

- **Status:** Accepted
- **Date:** 2026-05-01

## Context

A pure-asm project without a test harness is a project that ships bugs. The harness must be
built before the first asm function lands, because retrofitting tests across hundreds of
asm functions later is so expensive that it does not happen. Every project that has tried
to add tests "after the bring-up phase" has shipped without them.

The harness has multiple jobs:

1. Drive the C6 (over UART, USB-serial, and eventually the LoRa interface) with crafted
   inputs.
2. Capture and parse the structured log output (per ADR-0004).
3. Run the same input against an oracle (Python Reticulum reference, FIPS test vectors,
   our own Sail-emulated reference) and assert equivalence.
4. Dispatch to the correct formal verifier for each function category (per ADR-0006).
5. Be callable as a single command per function, both by humans and by AI agents in CI.

## Decision

A host-side Python test harness ships with the repository from milestone 1 and is mandatory
for every function. The harness:

1. **Lives in `tests/`** as Python 3.11+ modules, organized by `<module>/test_<function>.py`.
2. **Exposes one entry point per function:** `verify(target) -> VerifyResult`. The harness
   knows nothing about asm; it talks to a target abstraction.
3. **Targets:** the same test runs against three targets, in priority order. Pass criteria
   means "passes on every available target."
   - **`emu`** — qemu-system-riscv32, ideally with Sail-derived semantics. Fastest, no
     hardware required. The default target for agents.
   - **`hw`** — flashed Adafruit ESP32-C6 Feather over USB-serial. Required for hardware
     contract validation; slower (flashing per change is ~10 s).
   - **`oracle`** — for cryptographic and protocol functions, the upstream Python reference
     run as a subprocess. Provides differential testing: emu and hw output must match oracle
     output bit-for-bit.
4. **Single command:** `./verify <function_name>` from the repo root invokes:
   - the function's tests on every available target,
   - the function's formal verifier (per ADR-0006),
   - the constant-time check if `@ct: required`,
   - and emits a structured pass/fail summary.
5. **CI-callable:** the same command runs in CI on every PR. A function is not merge-eligible
   until `./verify` returns green for it. CI also runs `./verify --all` on a schedule for
   regression detection.
6. **Agent-friendly output:** structured JSON output mode (`./verify --json <function>`)
   makes it trivial for an AI agent to read pass/fail and act on failures without parsing
   text.
7. **No production code in Python.** The harness is exclusively for testing. The flashed
   binary contains no Python and no transpiled output of Python.

## Consequences

### Positive

- Every function gets a real test before it merges. The discipline is enforced by the
  workflow, not by hope.
- The differential-testing approach (oracle target) catches the entire class of bugs where
  our asm is internally consistent but disagrees with the reference. This is the dominant
  bug class in protocol implementations.
- AI agents have a clear, autonomous validation loop: write asm, run `./verify`, iterate
  until green. No human in the loop for routine work.
- Regression risk across the multi-year project is bounded: every existing function is
  re-verified on every CI run.

### Negative

- The harness itself is a real project — Python, target abstractions, log parser, oracle
  integrations. Milestone 1 budgets significant time for it. This is the cost of
  discipline.
- We commit to keeping Python in the dev environment forever. This is a tooling dependency,
  not a runtime dependency, but it is real.
- The `oracle` target requires keeping the upstream Python reference (`upstream/Reticulum/`)
  pinned and runnable. If upstream evolves in incompatible ways, we either pin a frozen
  version or update our oracle wrapper.

### Neutral

- Tests live alongside source, not in a parallel `tests/` tree mirroring `src/`. Actually,
  they do mirror — the ergonomic mirror is the right call. Open question: do we colocate
  asm and tests in the same directory or keep them separate? Current decision: separate,
  as stated above (`src/<module>/<function>.S` ↔ `tests/<module>/test_<function>.py`),
  because asm and Python have different toolchain expectations.

## Alternatives considered

**On-target test runner in asm.** Reject. Building a test framework in asm itself is a
substantial subproject and produces output that is harder to consume than host-side Python.
The flashed binary stays minimal; tests run on the host.

**Tests written per milestone, retrofitted to existing functions later.** Reject. This is
the failure mode every other project has hit. Tests are mandatory at function-introduction
time.

**Use an existing embedded test framework (Unity, Throw The Switch, etc.).** Reject. These
are C-centric and assume a C runtime in the target. Our target has no C.

## References

- ADR-0004 — diagnostics, defines the log format the harness parses.
- ADR-0006 — formal verification, which `./verify` dispatches to.
- ADR-0007 — project structure, which defines where tests live.
- Milestone 1 spec — implements the harness skeleton.
