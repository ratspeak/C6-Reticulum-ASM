# Tools

Host-side scripts that enforce the project's structural rules. Every script
in this directory is invoked by `make ci` (and therefore by every commit
gate); none of them ship in the production binary.

## Inventory

| Script | Purpose | Invoked by |
|--------|---------|-----------|
| [`parse_spec.py`](parse_spec.py) | Parse + validate the `;; @field:` spec block at the top of every `.S` file (per [ADR-0007](../docs/adr/0007-project-structure.md)). | `make spec FILE=…`; the verify dispatcher; CI |
| [`check_registry.py`](check_registry.py) | Cross-check `FUNCTIONS.md` against `src/`: every registered non-planned function has a source file, every source-defined global is registered, every depends-on points at a real entry. | `make registry`; CI |

## Conventions

- All scripts are Python 3.11+ and stdlib-only unless noted in `tests/requirements.txt`.
- All scripts accept `--json` for machine-readable output (so an agent can
  consume failures without parsing prose).
- Errors go to stderr; structured output goes to stdout.
- Exit code 0 = pass, non-zero = fail. Warnings (e.g., `@status` mismatch
  between source and registry) do not affect the exit code.

## Adding a tool

1. Write the script in this directory.
2. Add a corresponding `tests/tools/test_<name>.py` covering the contract.
3. Wire it into `Makefile` (`make ci` should run it).
4. Add a row to the inventory above.

The tool's first commit must include its tests; tools without tests do not
get to gate other people's commits.
