# Source

RISC-V assembly sources, organized one function per file per [ADR-0007](../docs/adr/0007-project-structure.md).

## Layout

```
src/
├── README.md                   (this file)
├── include/
│   ├── config.S                capacity constants (buffer sizes, table caps)
│   ├── regs.S                  ESP32-C6 peripheral register addresses
│   ├── psabi.S                 RISC-V psABI register name aliases
│   └── errno.S                 status / error codes
├── state/
│   ├── uart.S                  .bss for UART ring buffers
│   ├── kiss.S                  .bss for KISS decoder state
│   └── ...                     one state file per module that has state
├── boot/
│   ├── _reset.S
│   ├── _init_bss.S
│   ├── _init_data.S
│   └── _main.S
├── clock/
├── uart/
├── log/
├── kiss/
├── packet/
├── crypto/                     (added in milestone 2)
│   ├── sha256/
│   ├── hmac/
│   ├── hkdf/
│   ├── aes/
│   ├── x25519/
│   ├── ed25519/
│   └── rng/
├── identity/                   (added in milestone 3)
├── flash/                      (added in milestone 4)
├── transport/                  (added in milestone 5)
├── link/                       (added in milestone 6)
├── resource/                   (added in milestone 7)
├── interface/
│   ├── spi/                    (added in milestone 8)
│   └── lora/                   (added in milestone 8)
└── lxmf/                       (added in milestone 9)
```

## Conventions

Every file:

- Starts with the spec block per [ADR-0007](../docs/adr/0007-project-structure.md). The spec
  block is mandatory and parsed by `tools/parse_spec.py`.
- Defines exactly one global symbol matching `@function`.
- Uses standard psABI register conventions per [ADR-0001](../docs/adr/0001-abi.md).
- Uses static memory only, with state in `src/state/<module>.S` per [ADR-0002](../docs/adr/0002-memory-model.md).
- Includes shared constants from `src/include/` rather than redefining locally.

## Adding a function

See the workflow in [../CLAUDE.md](../CLAUDE.md). Summary:

1. Open [FUNCTIONS.md](../FUNCTIONS.md), find a `planned` entry with no unmet dependencies.
2. Create the `.S` file with the spec block filled in and `unimp` as the body.
3. Update FUNCTIONS.md status to `in-progress`.
4. Write the test file in `tests/<module>/test_<function>.py`.
5. Write the verifier spec in `proofs/<module>/<function>.<ext>`.
6. Implement the asm.
7. Run `./verify <function>` until green.
8. Update FUNCTIONS.md status to `verified`.
9. Single commit.
