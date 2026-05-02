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

Per [ADR-0009](../docs/adr/0009-verifier-toolchain.md). See
[../proofs/README.md](../proofs/README.md) for the per-tier responsibility
matrix. Pinned versions are in [versions.lock](versions.lock).

The verifier toolchain installs to user-scope locations (`~/opt/galois`,
`~/.opam`, `~/.ghcup`) and is symlinked into `toolchain/local/bin/` so
nothing pollutes shell dotfiles. Python verifiers run inside
`toolchain/venv/`. Both `toolchain/local/` and `toolchain/venv/` are
gitignored — re-create them with the install commands below on a fresh
clone. The dispatcher (`./verify`) prepends `toolchain/local/bin` to PATH
for proof scripts automatically.

```bash
# Galois prebuilts (Cryptol, SAW + bundled SMT solvers).
mkdir -p ~/opt/galois && cd ~/opt/galois
curl -fsSLO https://github.com/GaloisInc/cryptol/releases/download/3.5.0/cryptol-3.5.0-macos-15-ARM64-with-solvers.tar.gz
curl -fsSLO https://github.com/GaloisInc/saw-script/releases/download/v1.5/saw-1.5-macos-15-ARM64-with-solvers.tar.gz
tar xzf cryptol-3.5.0-macos-15-ARM64-with-solvers.tar.gz
tar xzf saw-1.5-macos-15-ARM64-with-solvers.tar.gz

# GHC + cabal (Tier C-future path: macaw-riscv build).
curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | \
    BOOTSTRAP_HASKELL_NONINTERACTIVE=1 \
    BOOTSTRAP_HASKELL_GHC_VERSION=9.6.7 \
    BOOTSTRAP_HASKELL_CABAL_VERSION=3.10.3.0 \
    BOOTSTRAP_HASKELL_NO_UPGRADE=1 sh

# opam + Binsec/Rel (Tier B) + Sail (Tier E) + Coq (fiat-crypto).
brew install opam pkgconf
opam init --bare --disable-sandboxing --no-setup -y
opam switch create binsec ocaml-base-compiler.5.1.1 -y
eval "$(opam env --switch=binsec)"
opam install binsec sail coq -y --confirm-level=unsafe-yes

# angr (Tier C) in a project venv.
cd <repo>
python3 -m venv toolchain/venv
toolchain/venv/bin/pip install --upgrade pip
toolchain/venv/bin/pip install angr

# TLA+ Tools (Tier D).
mkdir -p ~/opt/tlaplus
curl -fsSL -o ~/opt/tlaplus/tla2tools.jar \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar

# Vendor read-only references (sail-riscv, fiat-crypto).
mkdir -p references && cd references
git clone --depth 1 https://github.com/riscv/sail-riscv.git
git clone --depth 1 https://github.com/mit-plv/fiat-crypto.git

# Project-local symlinks (toolchain/local/bin) — see toolchain/local/install.sh
# (or hand-symlink the binaries above into toolchain/local/bin/).
```

Confirm the install: `./verify sha256_init` should print
`pass / pass / pass` for spec-validate, tests, and verify (the verify
step runs Cryptol typecheck + SAW driver + angr binary equivalence).

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
