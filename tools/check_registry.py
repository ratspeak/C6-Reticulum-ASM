#!/usr/bin/env python3
"""FUNCTIONS.md ↔ src/ cross-checker.

Per FUNCTIONS.md, the CI build fails if:

1. A .S file in src/ defines a global symbol not registered.
2. A registered function with non-`planned` status has no source file.
3. A function references a `depends-on` that does not exist in the registry.

Also reports (warnings, not failures):

* Source files whose status in FUNCTIONS.md disagrees with the @status field
  in their spec block (per ADR-0007).

Functions whose name contains `*` (e.g., `x25519_field_*`) are wildcard
placeholders and are excluded from the per-function cross-check; the registry
text is still parsed for module bookkeeping.

Exits 0 on full agreement, 1 on any failure. Warnings do not affect exit code.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "tools"))
import parse_spec  # noqa: E402

STATUS_SYMBOLS = {
    "☐": "planned",
    "◐": "in-progress",
    "◑": "tested",
    "◉": "verified",
    "⊘": "superseded",
}
VALID_STATUS_WORDS = set(STATUS_SYMBOLS.values())

MODULE_HEADER_RE = re.compile(r"^##\s+Module:\s+`([^`]+)`\s*$")
TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")


@dataclasses.dataclass
class FuncEntry:
    name: str
    module: str
    status: str
    depends_on: list[str]
    adrs: list[str]


def _strip_md(cell: str) -> str:
    """Strip backticks and surrounding whitespace from a cell. Asterisks are
    preserved because they are meaningful (wildcard placeholders like
    `x25519_field_*`).
    """
    return cell.strip().strip("`").strip()


def _parse_status_cell(cell: str) -> str:
    """Extract a status word from a cell that may contain a symbol, a word, or both."""
    cell = cell.strip()
    if not cell:
        return ""
    first = cell[0]
    if first in STATUS_SYMBOLS:
        rest = cell[1:].strip()
        # Trust the symbol; if the trailing word disagrees, return symbol meaning.
        return STATUS_SYMBOLS[first]
    # No symbol: rely on the word.
    word = cell.split()[0].lower()
    return word if word in VALID_STATUS_WORDS else cell


def _parse_list_cell(cell: str) -> list[str]:
    """Parse a comma- or whitespace-separated cell into a list, dropping em-dashes."""
    cell = cell.strip()
    if cell in {"", "—", "-", "–"}:
        return []
    parts: list[str] = []
    for raw in re.split(r"[,\s]+", cell):
        raw = _strip_md(raw)
        if raw and raw not in {"—", "-", "–"}:
            parts.append(raw)
    return parts


def parse_registry(path: Path) -> list[FuncEntry]:
    """Parse FUNCTIONS.md into a flat list of FuncEntry."""
    text = path.read_text(encoding="utf-8")
    entries: list[FuncEntry] = []
    current_module: str | None = None
    in_table = False
    saw_header = False

    for line in text.splitlines():
        m = MODULE_HEADER_RE.match(line)
        if m:
            current_module = m.group(1)
            in_table = False
            saw_header = False
            continue

        row = TABLE_ROW_RE.match(line)
        if not row:
            in_table = False
            saw_header = False
            continue

        cells = [c.strip() for c in row.group(1).split("|")]

        # Recognise table header / separator rows: skip until past them.
        if not saw_header and cells and cells[0].lower() == "function":
            saw_header = True
            in_table = False
            continue
        if saw_header and not in_table:
            # Either separator (---|---|...) or a data row. The separator has
            # only dashes and colons; everything else is a data row.
            if all(set(c) <= set("-:") for c in cells if c):
                in_table = True
                continue
            # No separator (rare): assume immediate data rows.
            in_table = True

        if not in_table or not current_module:
            continue
        if len(cells) < 4:
            continue

        name_raw = cells[0]
        # Skip placeholder rows like "(functions added when milestone N is activated)".
        if name_raw.startswith("("):
            continue
        name = _strip_md(name_raw)
        if not name:
            continue

        status = _parse_status_cell(cells[1])
        depends = _parse_list_cell(cells[2])
        adrs = _parse_list_cell(cells[3])

        entries.append(
            FuncEntry(
                name=name,
                module=current_module,
                status=status,
                depends_on=depends,
                adrs=adrs,
            )
        )

    return entries


def _collect_src_globals(repo_root: Path) -> dict[str, Path]:
    """Map global symbol → source file path, scanning every src/**/*.S.

    A "global symbol" is any symbol declared with `.global` or `.globl`. The
    one-function-per-file rule (ADR-0007) means each .S in a module directory
    declares one global; state and include files do not declare functions.
    """
    src = repo_root / "src"
    if not src.is_dir():
        return {}
    globals_: dict[str, Path] = {}
    for path in sorted(src.rglob("*.S")):
        if "include" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*\.global?\s+([A-Za-z_]\w*)", text, re.MULTILINE):
            globals_[m.group(1)] = path
    return globals_


def check(repo_root: Path = REPO_ROOT) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    registry_path = repo_root / "FUNCTIONS.md"
    if not registry_path.is_file():
        return [f"FUNCTIONS.md not found at {registry_path}"], []

    entries = parse_registry(registry_path)
    by_name: dict[str, FuncEntry] = {}
    for e in entries:
        if e.name in by_name:
            errors.append(f"FUNCTIONS.md: duplicate entry for {e.name}")
            continue
        by_name[e.name] = e

    # Check 3: depends-on entries must exist in the registry. Wildcards
    # (e.g. `sha256_*`) are satisfied if any entry's name starts with the
    # prefix, which includes a wildcard entry of the same prefix.
    for e in by_name.values():
        for dep in e.depends_on:
            if "*" in dep:
                prefix = dep.rstrip("*")
                if not any(n.startswith(prefix) for n in by_name):
                    errors.append(
                        f"FUNCTIONS.md: {e.name} depends on wildcard {dep!r} "
                        f"but no matching registered function found"
                    )
                continue
            if dep not in by_name:
                errors.append(
                    f"FUNCTIONS.md: {e.name} depends on {dep!r} which is not registered"
                )

    # Check 1 & 2: source-file ↔ registry agreement.
    src_globals = _collect_src_globals(repo_root)
    for sym, path in src_globals.items():
        if sym not in by_name:
            errors.append(
                f"src: {path.relative_to(repo_root)} declares global {sym!r} "
                f"not registered in FUNCTIONS.md"
            )

    for name, entry in by_name.items():
        if "*" in name:
            continue  # wildcard placeholder; source files appear when expanded
        if entry.status == "planned":
            continue  # no source file expected yet
        if entry.status == "superseded":
            continue  # superseded entries kept for history; source may be gone
        if name not in src_globals:
            errors.append(
                f"FUNCTIONS.md: {name!r} status is {entry.status!r} "
                f"but no src/**/*.S declares it as global"
            )

    # Warning: spec-block @status disagrees with registry status.
    for name, entry in by_name.items():
        if "*" in name:
            continue
        path = src_globals.get(name)
        if path is None:
            continue
        try:
            spec = parse_spec.parse_spec(path)
        except parse_spec.SpecError as exc:
            warnings.append(f"{path.relative_to(repo_root)}: cannot parse spec: {exc}")
            continue
        spec_status = spec.fields.get("status", "")
        if spec_status and spec_status != entry.status:
            warnings.append(
                f"{path.relative_to(repo_root)}: spec @status {spec_status!r} "
                f"disagrees with FUNCTIONS.md {entry.status!r}"
            )

    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    errors, warnings = check(args.repo_root.resolve())

    if args.json:
        json.dump(
            {"errors": errors, "warnings": warnings},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        if not errors and not warnings:
            print("registry: ok")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
