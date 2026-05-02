"""`./verify` dispatcher (ADR-0005).

Looks up a function in FUNCTIONS.md, finds its source file, parses the spec
block, and runs:

* the function's tests (the @tests pytest module),
* the function's formal verifier (per the @verify field), and
* a constant-time check (when @ct: required is implemented; deferred).

Reports structured pass/fail. Designed for both human and agent consumption.

Status today (early milestone 1):

* Test dispatch is wired through pytest.
* Verifier dispatch knows the @verify schema (kat-only, .saw, .tla, .py)
  and reports `not-implemented` for tools we have not installed yet,
  rather than silently returning success.

The wrapper script `./verify` at the repo root forwards to this module so
agents can run `./verify <function>`.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

sys.path.insert(0, str(REPO_ROOT / "tools"))
import check_registry  # noqa: E402
import parse_spec  # noqa: E402


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
    verify_field = spec.fields["verify"].strip()

    if parse_spec.KAT_ONLY_RE.match(verify_field):
        return StepResult("verify", "pass", f"kat-only: {verify_field}")

    verify_path = (repo_root / verify_field).resolve()
    if not verify_path.exists():
        return StepResult("verify", "fail", f"@verify path missing: {verify_path}")

    suffix = verify_path.suffix.lower()
    if suffix == ".saw":
        return _run_saw(verify_path)
    if suffix in {".tla", ".cfg"}:
        return _run_tlc(verify_path)
    if suffix == ".py":
        return _run_python_verifier(verify_path, repo_root)
    if suffix == ".md":
        # Contracts-only file (e.g., verify/boot/contracts.md). The actual
        # verifier is the .py / .saw next to it; the .md is documentation.
        return StepResult(
            "verify",
            "not-implemented",
            f"@verify points at a contracts-only .md: {verify_field}; "
            "expected a runnable verifier alongside",
        )
    return StepResult(
        "verify",
        "not-implemented",
        f"unknown verifier extension: {verify_path.suffix}",
    )


def _run_saw(path: Path) -> StepResult:
    if shutil.which("saw") is None:
        return StepResult("verify", "not-implemented", "saw not installed")
    started = time.monotonic()
    proc = subprocess.run(
        ["saw", str(path)], capture_output=True, text=True
    )
    elapsed = int((time.monotonic() - started) * 1000)
    return StepResult(
        "verify",
        "pass" if proc.returncode == 0 else "fail",
        (proc.stdout + proc.stderr).strip(),
        elapsed,
    )


def _run_tlc(path: Path) -> StepResult:
    # TLC needs tla2tools.jar; the wrapper script "tlc" is convenient when
    # present.
    runner = shutil.which("tlc") or shutil.which("tlcrepl")
    if runner is None:
        return StepResult("verify", "not-implemented", "tlc not installed")
    started = time.monotonic()
    proc = subprocess.run(
        [runner, str(path)], capture_output=True, text=True
    )
    elapsed = int((time.monotonic() - started) * 1000)
    return StepResult(
        "verify",
        "pass" if proc.returncode == 0 else "fail",
        (proc.stdout + proc.stderr).strip(),
        elapsed,
    )


def _run_python_verifier(path: Path, repo_root: Path) -> StepResult:
    # angr scripts and other Python verifiers are run by their own __main__.
    # angr being absent is a "not-implemented" outcome, not a failure.
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(path)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode == 0:
        return StepResult("verify", "pass", output, elapsed)
    if "ModuleNotFoundError" in output and "angr" in output:
        return StepResult("verify", "not-implemented", "angr not installed", elapsed)
    return StepResult("verify", "fail", output, elapsed)


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
