# Toolchain

Tools required to build, flash, emulate, test, and verify this project.

This document describes *what* and *why*. Specific versions are pinned in
[versions.lock](versions.lock) (created in milestone 1). Updating a pinned version requires
re-running `./verify --all` and committing only if green.

## Required tools

### Assembly + linking

Per [ADR-0008](../docs/adr/0008-naming-toolchain-format.md) we use vanilla
`riscv64-elf-binutils` (multilib) and target RV32IMAC explicitly via
`-march=rv32imac -mabi=ilp32`. The Espressif crosstool-NG fork remains a supported
substitution but is not the default.

- **`riscv64-elf-as`** — assembler. Vanilla GNU binutils.
- **`riscv64-elf-ld`** — linker. Same toolchain.
- **`riscv64-elf-objcopy`** — for producing flashable `.bin` from linked `.elf`.
- **`riscv64-elf-objdump`** — for disassembly during debugging and verifier input.

Install (macOS): `brew install riscv64-elf-binutils`. Linux: distribution
binutils (`riscv64-linux-gnu-binutils-elf` etc.) or build from source.

The Espressif boot ROM image format is independent of the assembler choice; we document and
emit it ourselves at link time (see [docs/hardware/image-header.md](../docs/hardware/image-header.md),
to be written during milestone 1).

### Flashing

- **`esptool.py`** — Espressif's flasher. Talks to the C6's boot ROM over UART or USB to
  write the binary to flash.

Install: `pip install esptool`.

### Emulation

- **`qemu-system-riscv32`** — emulates a generic RV32 system. We configure it with a device
  tree that approximates the C6's peripheral layout. Used as the `emu` target in the test
  harness.

Install: distribution package, or build from source. Sail-derived qemu builds are preferred
when available (they validate against the formal ISA model); document the choice in
`versions.lock`.

### Test harness

- **Python 3.11+**
- **`pyserial`** — UART communication with the `hw` target.
- **`pytest`** — test runner.
- **`rns`** (the upstream Python Reticulum) — used by the `oracle` target for differential
  testing.

Install: `pip install -r requirements.txt` (created in milestone 1).

### Verifiers

Per-category. See [../verify/README.md](../verify/README.md) for detail.

Milestone 1 minimum:
- **`angr`** — symbolic execution. `pip install angr`.
- **`tlc`** (TLA+ TLC model checker) — for state-machine specs. Install via `tla2tools.jar`
  from `github.com/tlaplus/tlaplus`.

Milestone 2 adds:
- **`saw`** (Software Analysis Workbench) and **`cryptol`** for crypto equivalence proofs.
- **`fiat-crypto`** for verified field arithmetic generation.
- **`ct-verif`** or **`Binsec/Rel`** for constant-time verification.

Defer install of milestone-2 verifiers until that milestone is activated.

## Versions

See [versions.lock](versions.lock).

## Updating a version

1. Bump the entry in `versions.lock`.
2. Reinstall locally.
3. Run `./verify --all` from the repo root.
4. If green, commit `versions.lock` (and any other changes the new version forced).
5. If red, either fix the breakage or revert the bump.

## Known toolchain gaps

| Gap | Impact | Plan |
|-----|--------|------|
| `qemu-system-riscv32`'s C6 model is incomplete | Some peripherals (USB, RNG, certain GPIO behaviors) may not emulate. | Mark which functions can be `emu`-tested in their spec block; route hardware-only paths to `hw` target. |
| Espressif boot ROM image header format poorly documented | Bring-up of flashable binary may take longer than estimated. | Reverse-engineer from `esp-idf/components/esp_app_format/`; document in `docs/hardware/image-header.md`. |
| Sail RISC-V model does not cover Espressif-specific extensions | We only use baseline RV32IMAC, so this should not bite us. | If we ever depend on a vendor-specific instruction, document it in an ADR and accept the verification gap. |
