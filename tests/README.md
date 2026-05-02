# Test harness

Host-side Python test harness, mandated by [ADR-0005](../docs/adr/0005-test-harness.md).

## Layout

```
tests/
├── README.md                    (this file)
├── requirements.txt             (Python dependencies)
├── conftest.py                  (pytest fixtures, target selection)
├── harness/
│   ├── target.py                Target abstraction (Emu, Hw, Oracle)
│   ├── log_parser.py            ADR-0004 log format parser
│   ├── verify.py                ./verify dispatcher
│   └── fixtures.py              shared test data, KAT vectors
├── boot/                        per-function tests, mirroring src/boot/
├── clock/
├── uart/
├── log/
├── kiss/
├── packet/
├── crypto/                      (added in milestone 2)
├── identity/                    (added in milestone 3)
├── transport/                   (added in milestone 5)
└── tools/                       tests for tools/ (parse_spec.py, etc.)
```

## Targets

A target is something a test can drive with input and read output from. The harness defines
three:

### `EmuTarget`

Drives `qemu-system-riscv32` with a flashed `.bin`. Fast: a full test run is seconds.
Default for agent work — most tests run here first, then on `hw` for confirmation.

Limitations: peripheral fidelity depends on qemu's C6 model. Functions that depend on
hardware-specific behavior (RNG entropy, USB Serial/JTAG, certain GPIO modes) may be
`hw`-only and are marked as such in their test file.

### `HwTarget`

Drives a physical Adafruit ESP32-C6 Feather over USB-serial. Flashes via `esptool.py` per
test run (or per session if test data does not change between cases). Slower (~10 s flash),
but is ground truth for hardware-touching functions.

A test that passes on `emu` but fails on `hw` indicates either a qemu gap (document in
`docs/hardware/qemu-gaps.md`) or an incorrect assumption in the asm.

### `OracleTarget`

Runs a subprocess `python3 -m RNS.Utilities.rnsd` (or for cryptography, the relevant Python
module from `cryptography` / `pynacl`) and uses it as a reference. Used for differential
testing: test input is fed to both the C6 (`emu` or `hw`) and the oracle, and outputs are
asserted byte-identical.

The oracle target is required for any function that has a reference implementation in
upstream Python.

## Test contract

Every test file exposes a `verify(target: Target) -> VerifyResult` entry point.
`VerifyResult` is a dataclass:

```python
@dataclass
class VerifyResult:
    function: str
    target: str          # "emu", "hw", or "oracle"
    passed: bool
    duration_ms: int
    cases: list[CaseResult]
    output: str          # captured log output
```

A function's overall verification passes only if `verify` returns `passed=True` on every
applicable target.

## Running tests

```bash
# Single function, default targets
./verify kiss_decode_byte

# Single function, JSON output (for agent consumption)
./verify --json kiss_decode_byte

# Specific target only
./verify --target emu kiss_decode_byte

# All functions (CI)
./verify --all

# All functions in a module
./verify --module kiss
```

## Writing a test

Test files mirror `src/` layout: `tests/<module>/test_<function>.py`.

A test:

1. Loads the function's spec block (via `tools/parse_spec.py`).
2. Defines a list of test cases (input → expected output, or input → expected log events).
3. For each case: configures the target, sends the input, captures output, asserts equality.
4. Returns a `VerifyResult`.

Cases include: positive cases, boundary cases, malformed inputs (parser must reject without
crashing), and KAT vectors where the function category warrants them.

## Continuous integration

The repository is local-only per ADR-0003 (no remote). CI runs locally via a pre-push git
hook that invokes `make ci`, which is `./verify --all` plus the static checks in
`tools/`. A push fails if `make ci` is red.

If a remote is later added (would require a new ADR), the same `make ci` becomes the CI
target on the remote.
