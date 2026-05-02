# ADR-0002: Static-only memory model, no heap

- **Status:** Accepted
- **Date:** 2026-05-01

## Context

The ESP32-C6 has 320 KB of HP SRAM and 16 KB of LP SRAM. There is no MMU, no virtual memory,
and no operating system in our binary. Every byte of RAM is ours to manage directly.

Reticulum's runtime state has bounded structure: identity (~256 bytes), destination cache
(N entries × ~64 bytes), path cache (N entries × ~80 bytes), per-link state (~1 KB),
KISS RX/TX buffers (~MTU each), packet processing scratch. The bounds are configurable but
known at build time.

We have to choose how RAM is allocated. Three families of approach:

1. **Heap allocation** (malloc/free or equivalent). Maximum flexibility at the cost of
   fragmentation, allocation failures, harder verification, and significant asm code for the
   allocator itself.
2. **Bump allocator with a single arena.** Simpler than a heap but still introduces a runtime
   allocation point that can fail and is harder to reason about formally.
3. **Static allocation only** — every state structure is a named symbol in `.bss`, sized at
   link time. No allocation happens at runtime; all RAM is accounted for by the linker.

## Decision

All RAM in this project is statically allocated at link time. There is no heap, no bump
allocator, no runtime allocation primitive of any kind in the production binary.

Specifically:

- Every persistent or scratch buffer is a named symbol declared in a dedicated state file
  under `src/state/<module>.S` with a `.bss` or `.data` directive.
- Buffer sizes are compile-time constants defined in `src/include/config.S` (capacities for
  caches, MTU sizes, etc.). Changing a capacity is a relink, not a runtime configuration.
- The linker script (`toolchain/c6.ld`) places every section at a known address and produces
  a memory map that accounts for 100% of RAM use. The build fails if total static use exceeds
  the available RAM minus a configured stack reservation.
- Functions that need scratch space either use the stack (bounded, tracked in the `@stack`
  field of the spec block) or accept a caller-provided buffer pointer.
- "Allocation" at the API level is replaced with "claim a slot from a fixed-size table." The
  table is full or it is not; there is no in-between, no fragmentation, no malloc failure to
  handle.

## Consequences

### Positive

- The RAM budget is knowable from the linker output. There is no class of bug called "ran out
  of memory at runtime in production after six hours."
- Formal verification is dramatically simpler. Every memory access is at a known address with
  known bounds; symbolic execution does not have to model an allocator.
- No fragmentation, no allocator state, no allocation failures to plumb through every call path.
- The boot sequence is trivial: clear `.bss`, copy `.data` from flash, jump to `main`. No
  allocator init, no heap walk.

### Negative

- Capacity decisions are committed at build time. If we want a larger destination cache, we
  re-link. We cannot dynamically grow caches in response to network conditions.
- Some Reticulum data structures (e.g., variable-length packet payloads) require allocation
  *style* even if not heap-style. We handle these with fixed-size pools; the largest
  payload size is bounded by Reticulum's MDU.
- Functions that would naturally take ownership of allocated memory must instead borrow
  caller-provided buffers, or claim/release pool slots explicitly. The discipline shows up
  in the `@inputs`/`@outputs` blocks.

### Neutral

- The stack is the one exception: it is allocated at link time but used dynamically. Each
  function's `@stack` field declares its maximum frame size; a static analyzer (built as part
  of the harness) computes worst-case stack depth across the call graph and asserts it fits
  the reserved stack region.

## Alternatives considered

**Heap allocator (e.g., a small dlmalloc port).** Reject. Adds a substantial asm component
(the allocator itself), introduces a class of runtime failures we would have to formally model
in every dependent function, and offers benefits (flexibility) we do not need.

**Single-arena bump allocator with periodic full reset.** Reject. Reticulum's state is long-lived
(identity, caches), not request-scoped, so a reset point does not exist naturally. A bump
allocator without a reset is a leak.

**Object pools with reference counting.** Reject. Overlaps with our fixed-size pool approach
but adds reference-count machinery we do not need. Pools without refcounts (claim/release with
explicit ownership) achieve the same end with less code.

## References

- ADR-0001 — calling convention, which defines stack discipline.
- ADR-0006 — formal verification, which depends on this decision.
- `toolchain/c6.ld` — the linker script that enforces the static memory map (created in
  milestone 1).
- `src/include/config.S` — the single source of truth for capacity constants (created in
  milestone 1).
