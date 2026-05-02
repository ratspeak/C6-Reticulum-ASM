"""Tests for tools/parse_spec.py."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import parse_spec

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# --- structural parse ----------------------------------------------------


def test_parse_minimum_block(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "foo.S",
        """\
        ;; ============================================================================
        ;; @function:    foo
        ;; @module:      bar
        ;; @inputs:      a0 = thing
        ;; @outputs:     a0 = result
        ;; @clobbers:    t0
        ;; @preserves:
        ;; @stack:       0
        ;; @cycles:      10
        ;; @ct:          not-required
        ;; @spec:        none
        ;; @verify:      kat-only; trivial helper, no functional contract
        ;; @tests:       tests/bar/test_foo.py
        ;; @adrs:        0001
        ;; @status:      draft
        ;; ============================================================================
                .global foo
        foo:    ret
        """,
    )
    spec = parse_spec.parse_spec(src)
    assert spec.fields["function"] == "foo"
    assert spec.fields["module"] == "bar"
    assert spec.fields["status"] == "draft"
    assert spec.line_range[0] == 1


def test_missing_opening_fence_raises(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "foo.S",
        """\
        ;; @function: foo
        """,
    )
    with pytest.raises(parse_spec.SpecError):
        parse_spec.parse_spec(src)


def test_missing_closing_fence_raises(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "foo.S",
        """\
        ;; ============================================================================
        ;; @function: foo
        """,
    )
    with pytest.raises(parse_spec.SpecError):
        parse_spec.parse_spec(src)


def test_duplicate_field_raises(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "foo.S",
        """\
        ;; ============================================================================
        ;; @function: foo
        ;; @function: bar
        ;; ============================================================================
        """,
    )
    with pytest.raises(parse_spec.SpecError, match="duplicate field"):
        parse_spec.parse_spec(src)


def test_inline_comment_stripped(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "foo.S",
        """\
        ;; ============================================================================
        ;; @stack:    16   # one frame for ra
        ;; ============================================================================
        """,
    )
    spec = parse_spec.parse_spec(src)
    assert spec.fields["stack"] == "16"


# --- validation ----------------------------------------------------------


def _fake_repo(tmp_path: Path) -> Path:
    """Build a minimal repo with one Accepted ADR and the dirs validate_spec
    inspects.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "tests" / "bar").mkdir(parents=True)
    (tmp_path / "tests" / "bar" / "test_foo.py").touch()
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "0001-fake.md").write_text(
        "# ADR-0001: Fake\n\n- **Status:** Accepted\n",
        encoding="utf-8",
    )
    return tmp_path


def _good_spec_body(extra: str = "") -> str:
    return (
        ";; ============================================================================\n"
        ";; @function:    foo\n"
        ";; @module:      bar\n"
        ";; @inputs:      a0 = thing\n"
        ";; @outputs:     a0 = result\n"
        ";; @clobbers:    t0\n"
        ";; @preserves:\n"
        ";; @stack:       0\n"
        ";; @cycles:      10\n"
        ";; @ct:          not-required\n"
        ";; @spec:        none\n"
        ";; @verify:      kat-only; trivial\n"
        ";; @tests:       tests/bar/test_foo.py\n"
        ";; @adrs:        0001\n"
        ";; @status:      draft\n"
        ";; ============================================================================\n"
        + extra
    )


def test_valid_spec_no_errors(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    f = src / "foo.S"
    f.write_text(_good_spec_body(), encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errors = parse_spec.validate_spec(spec, repo_root=repo)
    assert errors == [], errors


def test_function_must_match_basename(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body().replace("@function:    foo", "@function:    nope")
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("does not match file basename" in e for e in errs), errs


def test_unaccepted_adr_rejected(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body().replace("@adrs:        0001", "@adrs:        0099")
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("ADR-0099" in e for e in errs), errs


def test_kat_only_requires_rationale(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body().replace(
        "@verify:      kat-only; trivial",
        "@verify:      kat-only",
    )
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("rationale" in e for e in errs), errs


def test_unbounded_cycles_requires_no_ct(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body()
    body = body.replace("@cycles:      10", "@cycles:      unbounded")
    body = body.replace("@ct:          not-required", "@ct:          required")
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("unbounded" in e and "ct" in e for e in errs), errs


def test_module_must_match_directory(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body().replace("@module:      bar", "@module:      baz")
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("does not match directory" in e for e in errs), errs


def test_missing_field_reported(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path)
    src = repo / "src" / "bar"
    src.mkdir()
    body = _good_spec_body().replace(
        ";; @stack:       0\n", ""
    )
    f = src / "foo.S"
    f.write_text(body, encoding="utf-8")
    spec = parse_spec.parse_spec(f)
    errs = parse_spec.validate_spec(spec, repo_root=repo)
    assert any("missing field @stack" in e for e in errs), errs
