#!/usr/bin/env python3
"""Spec-block parser for assembly source files.

Per ADR-0007, every `src/**/*.S` file begins with a machine-readable spec block.
This parser extracts the block, validates every required field, and cross-checks
referenced files and ADRs against the filesystem.

Usage:
    parse_spec.py <path/to/file.S>           parse + validate, exit 0 on success
    parse_spec.py --json <path/to/file.S>    JSON output to stdout
    parse_spec.py --all                      all .S files under src/
    parse_spec.py --all --json               JSON list of all spec blocks

Exits 0 if every parsed block validates; non-zero otherwise. Errors go to stderr
in human-readable form regardless of --json mode (so an agent reading JSON also
sees diagnostics).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FIELDS = (
    "function",
    "module",
    "inputs",
    "outputs",
    "clobbers",
    "preserves",
    "stack",
    "cycles",
    "ct",
    "spec",
    "verify",
    "tests",
    "adrs",
    "status",
)

VALID_STATUS = {"draft", "review", "tested", "verified"}
VALID_CT = {"required", "not-required"}

# Header / footer fence the spec block. The prefix changed from `;;` to `#`
# in ADR-0008 because RISC-V GAS does not treat `;;` as a comment. We accept
# both prefixes during the transition; new files should use `#`.
FENCE_RE = re.compile(r"^\s*(?:#|;;)\s*={8,}\s*$")
FIELD_RE = re.compile(
    r"^\s*(?:#|;;)\s*@(?P<key>[a-zA-Z_]+)\s*:\s*(?P<value>.*?)\s*$"
)
COMMENT_RE = re.compile(r"^\s*(?:#|;;).*$")
ADR_FILE_RE = re.compile(r"^(\d{4})-[a-z0-9-]+\.md$")
KAT_ONLY_RE = re.compile(r"^kat-only(\s|$|;)")


@dataclasses.dataclass
class SpecBlock:
    """Parsed spec block. All fields are strings as written; validation
    interprets them.
    """

    path: Path
    fields: dict[str, str]
    line_range: tuple[int, int]  # 1-indexed, inclusive

    def to_dict(self) -> dict:
        return {
            "path": str(self.path.relative_to(REPO_ROOT))
            if self.path.is_absolute()
            else str(self.path),
            "fields": dict(self.fields),
            "line_range": list(self.line_range),
        }


class SpecError(Exception):
    """Raised when a spec block cannot be parsed (structural error). Validation
    errors are returned as a list, not raised.
    """


def _strip_inline_comment(value: str) -> str:
    """Drop trailing `# ...` rationale comments from a field value."""
    # Only strip a `#` that is preceded by whitespace, so values legitimately
    # containing `#` (rare in our format) are not corrupted.
    m = re.search(r"\s+#.*$", value)
    return value[: m.start()].rstrip() if m else value.rstrip()


def parse_spec(path: Path) -> SpecBlock:
    """Parse the spec block at the top of an assembly file.

    Raises SpecError if the block is missing or structurally malformed.
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Find the opening fence. We tolerate up to 5 leading blank lines or
    # comment lines that are not part of a spec block (none in practice, but
    # the rule is "spec block is at the top," not "line 1 is a fence").
    start_idx: int | None = None
    for i, line in enumerate(lines[:10]):
        if FENCE_RE.match(line):
            start_idx = i
            break

    if start_idx is None:
        raise SpecError(f"{path}: no spec block fence found in first 10 lines")

    # Find the closing fence after start.
    end_idx: int | None = None
    for j in range(start_idx + 1, len(lines)):
        if FENCE_RE.match(lines[j]):
            end_idx = j
            break

    if end_idx is None:
        raise SpecError(f"{path}: spec block opening fence has no closing fence")

    fields: dict[str, str] = {}
    body = lines[start_idx + 1 : end_idx]
    for k, line in enumerate(body, start=start_idx + 2):  # 1-indexed line numbers
        if not line.strip():
            continue
        m = FIELD_RE.match(line)
        if not m:
            # Tolerate unannotated comment lines inside the block (rationale text)
            # only if they start with `;;`. Anything else is an error.
            if COMMENT_RE.match(line):
                continue
            raise SpecError(f"{path}:{k}: malformed line inside spec block: {line!r}")
        key = m.group("key")
        value = _strip_inline_comment(m.group("value"))
        if key in fields:
            raise SpecError(f"{path}:{k}: duplicate field @{key}")
        fields[key] = value

    return SpecBlock(
        path=path,
        fields=fields,
        line_range=(start_idx + 1, end_idx + 1),
    )


def _accepted_adrs(repo_root: Path) -> set[str]:
    """Return the set of ADR numbers (zero-padded 4-digit strings) whose status
    line begins with `Accepted` or `Accepted (`.
    """
    adr_dir = repo_root / "docs" / "adr"
    accepted: set[str] = set()
    if not adr_dir.is_dir():
        return accepted
    for entry in adr_dir.iterdir():
        m = ADR_FILE_RE.match(entry.name)
        if not m:
            continue
        adr_num = m.group(1)
        head = entry.read_text(encoding="utf-8").splitlines()[:6]
        for line in head:
            sline = line.strip().lower()
            if sline.startswith("- **status:**") or sline.startswith("**status:**"):
                if "accepted" in sline:
                    accepted.add(adr_num)
                break
    return accepted


def validate_spec(
    spec: SpecBlock,
    *,
    repo_root: Path = REPO_ROOT,
    accepted_adrs: set[str] | None = None,
) -> list[str]:
    """Return a list of human-readable validation errors. Empty means valid."""
    errors: list[str] = []
    f = spec.fields
    rel = spec.path.relative_to(repo_root) if spec.path.is_absolute() else spec.path

    # 1. Required fields present.
    for name in REQUIRED_FIELDS:
        if name not in f:
            errors.append(f"{rel}: missing field @{name}")
    if errors:
        # Don't proceed with cross-checks if structural fields are missing.
        return errors

    # 2. @function matches the file basename.
    expected_fn = spec.path.stem
    if f["function"] != expected_fn:
        errors.append(
            f"{rel}: @function {f['function']!r} does not match file basename "
            f"{expected_fn!r}"
        )

    # 3. @status is one of the legal values.
    if f["status"] not in VALID_STATUS:
        errors.append(
            f"{rel}: @status {f['status']!r} not in {sorted(VALID_STATUS)}"
        )

    # 4. @ct is one of the legal values.
    if f["ct"] not in VALID_CT:
        errors.append(f"{rel}: @ct {f['ct']!r} not in {sorted(VALID_CT)}")

    # 5. @stack is a non-negative integer.
    try:
        stack = int(f["stack"])
        if stack < 0:
            errors.append(f"{rel}: @stack {stack} is negative")
    except ValueError:
        errors.append(f"{rel}: @stack {f['stack']!r} is not an integer")

    # 6. @cycles is an integer or "unbounded"; if unbounded, @ct must be not-required.
    cycles_raw = f["cycles"]
    cycles_unbounded = cycles_raw.strip().lower() == "unbounded"
    if not cycles_unbounded:
        # Permit forms like "~50", "bounded (~50)" with a digit somewhere — we
        # only require there be at least one decimal number for tooling to use.
        # Anything stricter forbids legitimate "approximate" annotations.
        if not re.search(r"\d", cycles_raw):
            errors.append(
                f"{rel}: @cycles {cycles_raw!r} has no integer and is not 'unbounded'"
            )
    else:
        if f["ct"] != "not-required":
            errors.append(
                f"{rel}: @cycles unbounded requires @ct: not-required (got {f['ct']!r})"
            )

    # 7. @adrs references exist as Accepted ADRs.
    if accepted_adrs is None:
        accepted_adrs = _accepted_adrs(repo_root)
    adrs_field = f["adrs"].strip()
    if adrs_field and adrs_field != "—":
        for raw in re.split(r"[,\s]+", adrs_field):
            if not raw:
                continue
            num = raw.zfill(4)
            if not re.fullmatch(r"\d{4}", num):
                errors.append(f"{rel}: @adrs entry {raw!r} is not a number")
                continue
            if num not in accepted_adrs:
                errors.append(
                    f"{rel}: @adrs references ADR-{num} which is not Accepted"
                )

    # 8. @verify either points at a real file or is "kat-only [rationale]".
    verify_field = f["verify"].strip()
    if KAT_ONLY_RE.match(verify_field):
        # Require a rationale after kat-only — bare "kat-only" is too easy to
        # leave on a function that should have a real verifier.
        if verify_field.strip().lower() == "kat-only":
            errors.append(
                f"{rel}: @verify 'kat-only' must include a rationale "
                f"(e.g. 'kat-only; entry-point semantics, no functional contract')"
            )
    else:
        verify_path = repo_root / verify_field
        if not verify_path.exists():
            errors.append(f"{rel}: @verify path {verify_field!r} does not exist")

    # 9. @tests points at a real file (or "none" with rationale, future).
    tests_field = f["tests"].strip()
    tests_path = repo_root / tests_field
    if not tests_path.exists():
        errors.append(f"{rel}: @tests path {tests_field!r} does not exist")

    # 10. @module matches the directory under src/ that the file lives in.
    try:
        rel_to_src = spec.path.resolve().relative_to((repo_root / "src").resolve())
        # Module is everything up to (but not including) the file.
        module_from_path = "/".join(rel_to_src.parts[:-1])
        # A few exceptions: state/ files declare their owning module; include/
        # files have no functions. We only check src/<module>/<function>.S.
        if module_from_path and not module_from_path.startswith(("state", "include")):
            if f["module"] != module_from_path:
                errors.append(
                    f"{rel}: @module {f['module']!r} does not match directory "
                    f"{module_from_path!r}"
                )
    except ValueError:
        # File outside src/. Skip the module-vs-path check.
        pass

    return errors


def _iter_src_files(repo_root: Path) -> list[Path]:
    src = repo_root / "src"
    if not src.is_dir():
        return []
    files: list[Path] = []
    for path in sorted(src.rglob("*.S")):
        # State and include files do not host functions, but per the spec block
        # convention every .S still carries a header. For now, skip include/
        # (pure equates) and require state/ to have one. Revisit when state/
        # files arrive.
        if "include" in path.parts:
            continue
        files.append(path)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="Single .S file to parse")
    parser.add_argument("--all", action="store_true", help="Parse every .S in src/")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (default: parent of tools/)",
    )
    args = parser.parse_args(argv)

    if args.all and args.path:
        parser.error("--all and a positional path are mutually exclusive")
    if not args.all and not args.path:
        parser.error("provide a path or --all")

    repo_root = args.repo_root.resolve()
    accepted = _accepted_adrs(repo_root)

    paths = (
        _iter_src_files(repo_root) if args.all else [Path(args.path).resolve()]
    )

    results: list[dict] = []
    all_errors: list[str] = []
    for path in paths:
        try:
            spec = parse_spec(path)
        except SpecError as exc:
            all_errors.append(str(exc))
            results.append({"path": str(path), "error": str(exc)})
            continue
        errors = validate_spec(spec, repo_root=repo_root, accepted_adrs=accepted)
        all_errors.extend(errors)
        entry = spec.to_dict()
        entry["errors"] = errors
        results.append(entry)

    if args.json:
        json.dump(results if args.all else results[0], sys.stdout, indent=2)
        sys.stdout.write("\n")

    for err in all_errors:
        print(err, file=sys.stderr)

    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
