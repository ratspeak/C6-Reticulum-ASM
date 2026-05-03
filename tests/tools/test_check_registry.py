"""Tests for tools/check_registry.py."""

from __future__ import annotations

import textwrap
from pathlib import Path

import check_registry

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# --- registry parsing ----------------------------------------------------


def test_parse_basic_registry(tmp_path: Path) -> None:
    md = tmp_path / "FUNCTIONS.md"
    md.write_text(
        textwrap.dedent(
            """\
            # Function Registry

            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `_reset` | ☐ planned | — | 0001, 0002 | (spec) |
            | `_init_bss` | ◑ tested | `_reset` | 0002 | (spec) |

            ## Module: `clock`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `clock_init` | ◉ verified | — | — | (spec) |
            """
        ),
        encoding="utf-8",
    )
    entries = check_registry.parse_registry(md)
    by_name = {e.name: e for e in entries}
    assert by_name["_reset"].status == "planned"
    assert by_name["_reset"].module == "boot"
    assert by_name["_reset"].adrs == ["0001", "0002"]
    assert by_name["_init_bss"].depends_on == ["_reset"]
    assert by_name["_init_bss"].status == "tested"
    assert by_name["clock_init"].status == "verified"
    assert by_name["clock_init"].adrs == []


def test_parse_owner_column_registry(tmp_path: Path) -> None:
    md = tmp_path / "FUNCTIONS.md"
    md.write_text(
        textwrap.dedent(
            """\
            # Function Registry

            ## Module: `identity`

            | Function | Status | Owner | Depends-on | ADRs | Spec |
            |----------|--------|-------|-----------|------|------|
            | `identity_create` | ◐ in-progress | agent-2 | `rng_bytes` | 0001 | (spec) |
            | `identity_hash` | ☐ planned |  | `sha256_*` | — | (spec) |
            """
        ),
        encoding="utf-8",
    )
    entries = check_registry.parse_registry(md)
    by_name = {e.name: e for e in entries}
    assert by_name["identity_create"].status == "in-progress"
    assert by_name["identity_create"].owner == "agent-2"
    assert by_name["identity_create"].depends_on == ["rng_bytes"]
    assert by_name["identity_hash"].owner == ""
    assert by_name["identity_hash"].adrs == []


def test_skip_placeholder_rows(tmp_path: Path) -> None:
    md = tmp_path / "FUNCTIONS.md"
    md.write_text(
        textwrap.dedent(
            """\
            ## Module: `lxmf`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | (functions added when milestone 9 is activated) | ☐ planned | | | (spec) |
            """
        ),
        encoding="utf-8",
    )
    entries = check_registry.parse_registry(md)
    assert entries == []


def test_wildcard_entry_kept(tmp_path: Path) -> None:
    md = tmp_path / "FUNCTIONS.md"
    md.write_text(
        textwrap.dedent(
            """\
            ## Module: `crypto/x25519`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `x25519_field_*` | ☐ planned | — | 0006 | (spec) |
            | `x25519_scalar_mult` | ☐ planned | `x25519_field_*` | 0006 | (spec) |
            """
        ),
        encoding="utf-8",
    )
    entries = check_registry.parse_registry(md)
    by_name = {e.name: e for e in entries}
    assert "x25519_field_*" in by_name
    assert by_name["x25519_scalar_mult"].depends_on == ["x25519_field_*"]


# --- end-to-end check ---------------------------------------------------


def _make_repo(tmp_path: Path, *, registry: str, src_files: dict[str, str]) -> Path:
    (tmp_path / "FUNCTIONS.md").write_text(textwrap.dedent(registry), encoding="utf-8")
    (tmp_path / "src").mkdir()
    for rel, content in src_files.items():
        p = tmp_path / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content), encoding="utf-8")
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    (tmp_path / "docs" / "adr" / "0001-fake.md").write_text(
        "# ADR-0001\n\n- **Status:** Accepted\n", encoding="utf-8"
    )
    return tmp_path


SPEC_BODY = """\
;; ============================================================================
;; @function:    {name}
;; @module:      {module}
;; @inputs:      —
;; @outputs:     —
;; @clobbers:    —
;; @preserves:   —
;; @stack:       0
;; @cycles:      10
;; @ct:          not-required
;; @spec:        none
;; @verify:      kat-only; trivial
;; @tests:       FUNCTIONS.md
;; @adrs:        0001
;; @status:      {status}
;; ============================================================================
        .global {name}
        .type   {name}, @function
{name}: ret
"""


def test_unregistered_global_is_error(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        registry="""\
            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `known` | ◑ tested | — | 0001 | (spec) |
            """,
        src_files={
            "boot/known.S": SPEC_BODY.format(name="known", module="boot", status="tested"),
            "boot/extra.S": SPEC_BODY.format(name="extra", module="boot", status="tested"),
        },
    )
    errors, _ = check_registry.check(repo)
    assert any("extra" in e and "not registered" in e for e in errors), errors


def test_missing_source_for_non_planned_status_is_error(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        registry="""\
            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `gone` | ◉ verified | — | 0001 | (spec) |
            """,
        src_files={},
    )
    errors, _ = check_registry.check(repo)
    assert any("gone" in e and "no src" in e for e in errors), errors


def test_dep_to_unknown_is_error(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        registry="""\
            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `child` | ☐ planned | `ghost` | 0001 | (spec) |
            """,
        src_files={},
    )
    errors, _ = check_registry.check(repo)
    assert any("ghost" in e for e in errors), errors


def test_status_mismatch_is_warning_not_error(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        registry="""\
            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `known` | ◑ tested | — | 0001 | (spec) |
            """,
        src_files={
            "boot/known.S": SPEC_BODY.format(
                name="known", module="boot", status="verified"
            ),
        },
    )
    errors, warnings = check_registry.check(repo)
    assert errors == [], errors
    assert any("disagrees with FUNCTIONS.md" in w for w in warnings), warnings


def test_clean_repo_passes(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        registry="""\
            ## Module: `boot`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `known` | ◑ tested | — | 0001 | (spec) |
            """,
        src_files={
            "boot/known.S": SPEC_BODY.format(name="known", module="boot", status="tested"),
        },
    )
    errors, warnings = check_registry.check(repo)
    assert errors == [], errors
    assert warnings == [], warnings


def test_repo_root_registry_is_ok() -> None:
    """The committed FUNCTIONS.md must currently be self-consistent."""
    errors, _ = check_registry.check(REPO_ROOT)
    assert errors == [], errors
