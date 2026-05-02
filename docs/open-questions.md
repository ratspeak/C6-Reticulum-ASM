# Open questions

Issues surfaced during work that need a decision but don't yet have one.
Each entry has a short rationale and a proposed resolution. Items that
become decisions move into ADRs.

## Resolved

| OQ | Topic | Resolution |
|----|-------|------------|
| OQ-1 | `verify/` vs `./verify` collision | Resolved by [ADR-0008](adr/0008-naming-toolchain-format.md): rename `verify/` → `proofs/`. |
| OQ-2 | Espressif fork vs vanilla binutils | Resolved by [ADR-0008](adr/0008-naming-toolchain-format.md): vanilla `riscv64-elf-binutils`, target rv32imac via `-march`. |
| OQ-3 | Hex vs decimal log timestamps | Resolved by [ADR-0008](adr/0008-naming-toolchain-format.md): 8 hex digits, emitted by `log_hex(width=8)`. |
| OQ-4 | Defer `tools/check_stack.py` until call graph exists | Implemented now that `_main` calls into the bring-up chain. Wired into `make ci`; current binary's deepest reachable stack is 48 bytes (limit STACK_SIZE = 16384). |

The original entries are kept below for the audit trail.

---

## OQ-5: LoRa chip choice — SX1262 (decided 2026-05-02)

ADR-0003 and the references list pin SX1276/RFM95 as the milestone-8 LoRa
chip. The hardware on hand is a Wio SX1262 module (Seeed). Same LoRa
modulation, same RF math, different register map (SX1262 uses busy line
+ command opcodes; SX1276 is closer to a flat MMIO register file).

**Decision:** milestone 8 targets SX1262, not SX1276.

**Action items (deferred until milestone 8 activates):**

* Write ADR-0009: "SX1262 supersedes SX1276 in ADR-0003" — references the
  SX1262 datasheet (user will provide).
* Mark ADR-0003 status as `Accepted (partially superseded by ADR-0009 —
  chip choice)`.
* Replace `references/sx1276-datasheet.pdf` line in `references/README.md`
  with the SX1262 datasheet entry.
* The SPI driver and the Reticulum protocol layer above are unchanged;
  only the chip driver moves. Files become `src/interface/lora/sx1262_*`.

Power / wiring (unchanged by the chip swap): C6 USB-C is power + USB
Serial/JTAG dev only; the LoRa module talks SPI on the Feather header
pins (MOSI/MISO/SCK + CS GPIO + RST GPIO + BUSY (SX1262-specific) +
DIO1 IRQ). Bench power via USB-C, portable via the Feather's JST-2
LiPo connector.

---

## OQ-1: `verify/` directory and `./verify` command collide

CLAUDE.md, ADR-0005, and milestone-1.md all describe `./verify <function>`
as the single user-facing entry point for the test + formal-verifier
dispatcher. ADR-0007 also specifies that per-function verifier specs live
under `verify/<module>/<function>.<ext>` (a directory named `verify/`).

A POSIX filesystem cannot host both an executable file `verify` and a
directory `verify/` in the same parent. We need to resolve the name.

**Proposed:** rename the directory to `proofs/` (alternatively `formal/`).
"Proofs" matches the content (formal-method specs) and frees the name
`verify` for the dispatcher script. ADR-0008 captures the supersession of
the directory references in ADR-0006/0007 and the milestone-1 spec.

**Workaround in place today:** the dispatcher is invoked via
`make verify FN=<function>` or `python3 verify_cli.py <function>`. The
`./verify <function>` shell ergonomics are blocked on this rename.

## OQ-2: Toolchain — Espressif fork or vanilla binutils

Toolchain README pins `riscv32-esp-elf-as` (Espressif fork). Homebrew
provides `riscv64-elf-as` (vanilla binutils, multilib) which can target
RV32IMAC via `-march=rv32imac -mabi=ilp32`. The Espressif fork does not
ship via homebrew; users would download Espressif's crosstool-NG build.

**Tradeoffs:**

* Espressif fork: matches docs, includes pre-configured linker scripts
  for ESP image headers. Manual install. Larger trust base.
* Vanilla binutils: one `brew install riscv64-elf-binutils` away. We
  hand-write the linker script anyway (per ADR-0002), so the
  Espressif-specific helpers are not load-bearing.

**Proposed:** ADR-0008 (or 0009) adopts vanilla binutils. The toolchain
README's existing escape hatch ("a future ADR may replace this with a
pure binutils build") is invoked.

## OQ-3: Log timestamp format — hex or decimal

ADR-0004 specifies `<ts_ms>\t…` with the example `00012345`. The format
is ambiguous (hex `0x12345` = 74565ms; decimal would be 12345ms).

**Proposed:** hex. Cheapest to emit from asm (one `log_hex(width=8)`
call); consistent with the rest of the format which is hex. Documented
explicitly in `tests/harness/log_parser.py` and the eventual `log_event`
spec block. The parser's `LogEvent.ts_ms` field already follows this.

## OQ-4: `tools/check_stack.py` — defer until first .S exists

The static stack-depth analyzer is listed in milestone-1 deliverables.
Its inputs (the asm call graph from `call`/`jal` instructions) do not
exist yet. Premature implementation would force a synthetic test corpus
that won't survive contact with real asm.

**Proposed:** implement alongside the first non-leaf function (`_main`,
which calls into clock/uart/log). Track in FUNCTIONS.md by leaving the
stack-depth check absent from `make ci` until then.
