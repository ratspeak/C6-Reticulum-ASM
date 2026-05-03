"""`./verify` dispatcher (ADR-0005, extended by ADR-0009).

Looks up a function in FUNCTIONS.md, finds its source file, parses the spec
block, and runs:

* the function's tests (the @tests pytest module),
* every formal verifier listed in @verify (comma-separated paths), and
* a constant-time check via Binsec/Rel (when @ct: required; ADR-0009).

The @verify field is a comma-separated list of paths. Each path's suffix
selects its backend per ADR-0009:

  *.cry   Cryptol module — typecheck via `cryptol -c ':l <path>'`
  *.saw   SAW driver — proves Cryptol-Cryptol equivalence (Tier A)
  *.py    angr verifier — proves binary equivalence (Tier C)
  *.tla   TLA+ spec — TLC model-checks state machines (Tier D)
  *.cfg   TLA+ config — runs alongside *.tla
  *.bsc   Binsec/Rel constant-time script (Tier B)

A single 'kat-only; <rationale>' entry is permitted and treated as a pass
with the rationale recorded.

All proof scripts run with toolchain/local/bin prepended to PATH so the
project-local SAW, Cryptol, Binsec, Sail, and TLC binaries are found
without polluting the user's shell. Python verifiers run under
toolchain/venv/bin/python so angr is on sys.path.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLCHAIN_BIN = REPO_ROOT / "toolchain" / "local" / "bin"
VENV_PYTHON = REPO_ROOT / "toolchain" / "venv" / "bin" / "python"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import check_registry  # noqa: E402
import parse_spec  # noqa: E402


def _proof_env() -> dict[str, str]:
    """Subprocess env for proof scripts: prepend toolchain/local/bin to PATH
    and set CRYPTOLPATH so cross-module Cryptol imports resolve regardless
    of which proofs/<module>/ subdirectory the verifier lives in."""
    env = os.environ.copy()
    env["PATH"] = f"{TOOLCHAIN_BIN}:{env.get('PATH', '')}"
    proofs_root = REPO_ROOT / "proofs"
    if proofs_root.is_dir():
        cryptol_dirs = [str(p) for p in sorted(proofs_root.rglob("*"))
                        if p.is_dir()
                        and not p.name.startswith(".")
                        and p.name != "__pycache__"]
        existing = env.get("CRYPTOLPATH", "")
        env["CRYPTOLPATH"] = ":".join(cryptol_dirs + ([existing] if existing else []))
    return env


@dataclasses.dataclass
class StepResult:
    name: str
    status: str  # "pass" | "fail" | "skip" | "not-implemented"
    detail: str = ""
    duration_ms: int = 0


@dataclasses.dataclass
class FunctionResult:
    function: str
    overall: str  # "pass" | "fail" | "skip"
    steps: list[StepResult]

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "overall": self.overall,
            "steps": [dataclasses.asdict(s) for s in self.steps],
        }


# -------------------------------------------------------------------------
# Source-file lookup. We map `function` → `src/**/<function>.S` by walking
# src/ once and caching. Cheaper than re-grepping per call.
# -------------------------------------------------------------------------


def _source_index(repo_root: Path) -> dict[str, Path]:
    src = repo_root / "src"
    if not src.is_dir():
        return {}
    index: dict[str, Path] = {}
    for path in src.rglob("*.S"):
        if "include" in path.parts:
            continue
        index[path.stem] = path
    return index


# -------------------------------------------------------------------------
# Step runners.
# -------------------------------------------------------------------------


def _run_tests(spec: parse_spec.SpecBlock, repo_root: Path) -> StepResult:
    tests_path = (repo_root / spec.fields["tests"]).resolve()
    if not tests_path.exists():
        return StepResult("tests", "fail", f"@tests path missing: {tests_path}")

    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_path), "-q", "--no-header"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    detail = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return StepResult("tests", "pass", detail.strip().splitlines()[-1] if detail else "", elapsed)
    return StepResult("tests", "fail", detail, elapsed)


def _run_verifier(spec: parse_spec.SpecBlock, repo_root: Path) -> StepResult:
    """Dispatch every backend listed in @verify, aggregate into one StepResult.

    The @verify field is a comma-separated list per ADR-0009. A single
    "kat-only; <rationale>" entry shortcircuits to pass.
    """
    verify_field = spec.fields["verify"].strip()

    if parse_spec.KAT_ONLY_RE.match(verify_field):
        return StepResult("verify", "pass", f"kat-only: {verify_field}")

    sub_results: list[StepResult] = []
    overall = "pass"
    for raw in (p.strip() for p in verify_field.split(",")):
        if not raw:
            continue
        path = (repo_root / raw).resolve()
        if not path.exists():
            sub_results.append(StepResult(raw, "fail", f"@verify path missing: {path}"))
            overall = "fail"
            continue
        sub = _run_one_backend(path, repo_root)
        sub_results.append(sub)
        if sub.status == "fail":
            overall = "fail"
        elif sub.status == "not-implemented" and overall == "pass":
            overall = "not-implemented"

    detail_lines: list[str] = []
    total_ms = 0
    for s in sub_results:
        suffix = " ({}ms)".format(s.duration_ms) if s.duration_ms else ""
        detail_lines.append(f"  [{s.status}] {s.name}{suffix}")
        if s.detail and s.status in {"fail", "not-implemented"}:
            for line in s.detail.splitlines():
                detail_lines.append(f"    {line}")
        total_ms += s.duration_ms

    return StepResult(
        "verify",
        overall,
        "\n".join(detail_lines),
        total_ms,
    )


def _run_one_backend(path: Path, repo_root: Path) -> StepResult:
    rel = path.relative_to(repo_root) if path.is_absolute() else path
    suffix = path.suffix.lower()
    if suffix == ".cry":
        return _run_cryptol(path, str(rel))
    if suffix == ".saw":
        return _run_saw(path, str(rel))
    if suffix in {".tla", ".cfg"}:
        return _run_tlc(path, str(rel))
    if suffix == ".py":
        return _run_python_verifier(path, repo_root, str(rel))
    if suffix == ".bsc":
        return _run_binsec_ct(path, str(rel))
    if suffix == ".md":
        return StepResult(
            str(rel),
            "not-implemented",
            "contracts-only .md; expected a runnable verifier alongside",
        )
    return StepResult(
        str(rel),
        "not-implemented",
        f"unknown verifier extension: {suffix}",
    )


def _have(tool: str) -> bool:
    if (TOOLCHAIN_BIN / tool).exists():
        return True
    return shutil.which(tool) is not None


def _run_cryptol(path: Path, name: str) -> StepResult:
    if not _have("cryptol"):
        return StepResult(name, "not-implemented", "cryptol not installed")
    started = time.monotonic()
    proc = subprocess.run(
        ["cryptol", "-e", "-c", f":l {path}", "-c", ":quit"],
        env=_proof_env(),
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    out = (proc.stdout + proc.stderr).strip()
    # Cryptol exits 0 on a clean module load; non-zero or "[error]" lines fail.
    failed = proc.returncode != 0 or "[error]" in out.lower()
    return StepResult(
        name,
        "fail" if failed else "pass",
        out if failed else "module loaded clean",
        elapsed,
    )


def _run_saw(path: Path, name: str) -> StepResult:
    if not _have("saw"):
        return StepResult(name, "not-implemented", "saw not installed")
    started = time.monotonic()
    proc = subprocess.run(
        ["saw", str(path)],
        env=_proof_env(),
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    return StepResult(
        name,
        "pass" if proc.returncode == 0 else "fail",
        (proc.stdout + proc.stderr).strip(),
        elapsed,
    )


def _run_tlc(path: Path, name: str) -> StepResult:
    if not _have("tlc"):
        return StepResult(name, "not-implemented", "tlc not installed")
    started = time.monotonic()
    proc = subprocess.run(
        ["tlc", str(path)],
        env=_proof_env(),
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    return StepResult(
        name,
        "pass" if proc.returncode == 0 else "fail",
        (proc.stdout + proc.stderr).strip(),
        elapsed,
    )


def _run_python_verifier(path: Path, repo_root: Path, name: str) -> StepResult:
    """Run a .py verifier under the project venv (so angr is importable)."""
    interpreter = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    started = time.monotonic()
    proc = subprocess.run(
        [interpreter, str(path)],
        cwd=repo_root,
        env=_proof_env(),
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode == 0:
        return StepResult(name, "pass", output, elapsed)
    if "ModuleNotFoundError" in output and "angr" in output:
        return StepResult(name, "not-implemented", "angr not installed", elapsed)
    return StepResult(name, "fail", output, elapsed)


def _run_binsec_ct(path: Path, name: str) -> StepResult:
    """Constant-time check via Binsec/Rel (relational symbolic execution).

    The .bsc file is an SSE script (Binsec's own DSL — `starting from
    <symbol>`, `secret`, `assume`, `halt at`, etc.). The harness wires
    it to the qemu-virt firmware ELF and runs the constant-time checker.
    A 'secure' verdict from the checker (combined with a complete
    exploration — no warnings about pending paths) maps to a pass; an
    'insecure' verdict or any failed check maps to fail; an 'unknown'
    verdict maps to fail (incomplete proofs are not accepted)."""
    if not _have("binsec"):
        return StepResult(name, "not-implemented", "binsec not installed")
    elf = REPO_ROOT / "build" / "qemu-virt" / "firmware.elf"
    if not elf.exists():
        return StepResult(name, "fail",
                          f"{elf} missing — run `make build` first")
    started = time.monotonic()
    # -sse-depth: 524288 instructions per path. Default is 1000, which
    # is too tight for crypto wrappers (aes_subbytes ~5300, aes256_
    # encrypt_block ~66k). 524288 covers any single-function proof
    # without making per-path exploration unbounded; CBC modes with
    # multi-block messages or full ed25519_sign would need an explicit
    # bump in the harness if and when they get a Tier B proof.
    # -sse-timeout: 600 s per Binsec process.
    proc = subprocess.run(
        ["binsec", "-isa", "riscv32", "-sse", "-checkct",
         "-sse-depth", "524288", "-sse-timeout", "600",
         "-sse-script", str(path), str(elf)],
        env=_proof_env(),
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    output = (proc.stdout + proc.stderr).strip()
    # Binsec returns 0 even when the program is reported insecure, so
    # we parse the result line directly.
    secure = "Program status is : secure" in output
    return StepResult(
        name,
        "pass" if (proc.returncode == 0 and secure) else "fail",
        output,
        elapsed,
    )


# -------------------------------------------------------------------------
# Dispatch
# -------------------------------------------------------------------------


def _verify_function(
    name: str, repo_root: Path, source_index: dict[str, Path]
) -> FunctionResult:
    src = source_index.get(name)
    if src is None:
        return FunctionResult(
            name, "skip",
            [StepResult("source", "skip", f"no src/**/{name}.S yet")],
        )

    try:
        spec = parse_spec.parse_spec(src)
    except parse_spec.SpecError as exc:
        return FunctionResult(
            name, "fail", [StepResult("spec-parse", "fail", str(exc))]
        )

    spec_errs = parse_spec.validate_spec(spec, repo_root=repo_root)
    if spec_errs:
        return FunctionResult(
            name, "fail",
            [StepResult("spec-validate", "fail", "\n".join(spec_errs))],
        )

    steps = [
        StepResult("spec-validate", "pass"),
        _run_tests(spec, repo_root),
        _run_verifier(spec, repo_root),
    ]

    overall = "pass"
    for s in steps:
        if s.status == "fail":
            overall = "fail"
            break
    return FunctionResult(name, overall, steps)


def _all_registered(repo_root: Path) -> list[str]:
    entries = check_registry.parse_registry(repo_root / "FUNCTIONS.md")
    out: list[str] = []
    seen: set[str] = set()
    for e in entries:
        if "*" in e.name or e.name in seen:
            continue
        seen.add(e.name)
        out.append(e.name)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function", nargs="?", help="Function to verify")
    parser.add_argument("--all", action="store_true", help="Verify every registered function")
    parser.add_argument("--module", help="Verify every function in a module")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    if not args.function and not args.all and not args.module:
        parser.error("provide a function name or --all / --module")

    repo_root = args.repo_root.resolve()
    source_index = _source_index(repo_root)

    if args.all:
        names = _all_registered(repo_root)
    elif args.module:
        entries = check_registry.parse_registry(repo_root / "FUNCTIONS.md")
        names = [
            e.name for e in entries
            if e.module == args.module and "*" not in e.name
        ]
    else:
        names = [args.function]

    results = [_verify_function(n, repo_root, source_index) for n in names]

    if args.json:
        json.dump([r.to_dict() for r in results], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for r in results:
            print(f"== {r.function}: {r.overall} ==")
            for s in r.steps:
                line = f"  [{s.status}] {s.name}"
                if s.duration_ms:
                    line += f" ({s.duration_ms}ms)"
                print(line)
                if s.detail and s.status in {"fail", "not-implemented"}:
                    for detail_line in s.detail.splitlines():
                        print(f"      {detail_line}")

    return 1 if any(r.overall == "fail" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
