"""Tests for tools/check_stack.py."""

from __future__ import annotations

import textwrap
from pathlib import Path

import check_stack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


SPEC = """\
# ============================================================================
# @function:    {name}
# @module:      {module}
# @inputs:      —
# @outputs:     —
# @clobbers:    —
# @preserves:   —
# @stack:       {stack}
# @cycles:      10
# @ct:          not-required
# @spec:        none
# @verify:      kat-only; trivial
# @tests:       FUNCTIONS.md
# @adrs:        0001
# @status:      verified
# ============================================================================
        .global {name}
        .type   {name}, @function
{name}:
{body}
"""


def _make_repo(tmp_path: Path, funcs: list[dict]) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "include").mkdir()
    (tmp_path / "src" / "include" / "config.S").write_text(
        ".equ STACK_SIZE, 0x1000\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    (tmp_path / "docs" / "adr" / "0001-fake.md").write_text(
        "# ADR-0001\n\n- **Status:** Accepted\n", encoding="utf-8"
    )
    for f in funcs:
        p = tmp_path / "src" / f["module"] / f"{f['name']}.S"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            SPEC.format(
                name=f["name"],
                module=f["module"],
                stack=f["stack"],
                body=f["body"],
            ),
            encoding="utf-8",
        )
    return tmp_path


def test_single_leaf(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "_reset", "module": "boot", "stack": "0", "body": "        ret"}],
    )
    graph = check_stack.build_call_graph(repo)
    depth, path, warnings = check_stack.worst_case_path(graph, "_reset")
    assert depth == 0
    assert path == ["_reset"]
    assert warnings == []


def test_call_chain_sums(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "_reset", "module": "boot", "stack": "0",
             "body": "        call _a\n        ret"},
            {"name": "_a", "module": "boot", "stack": "16",
             "body": "        call _b\n        ret"},
            {"name": "_b", "module": "boot", "stack": "32",
             "body": "        ret"},
        ],
    )
    graph = check_stack.build_call_graph(repo)
    depth, path, warnings = check_stack.worst_case_path(graph, "_reset")
    assert depth == 48  # 0 + 16 + 32
    assert path == ["_reset", "_a", "_b"]


def test_picks_deeper_branch(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "_reset", "module": "boot", "stack": "0",
             "body": "        call _shallow\n        call _deep\n        ret"},
            {"name": "_shallow", "module": "boot", "stack": "8",
             "body": "        ret"},
            {"name": "_deep", "module": "boot", "stack": "64",
             "body": "        ret"},
        ],
    )
    graph = check_stack.build_call_graph(repo)
    depth, path, warnings = check_stack.worst_case_path(graph, "_reset")
    assert depth == 64
    assert path == ["_reset", "_deep"]


def test_recursion_detected(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "_reset", "module": "boot", "stack": "0",
             "body": "        call _loop\n        ret"},
            {"name": "_loop", "module": "boot", "stack": "16",
             "body": "        call _loop\n        ret"},
        ],
    )
    graph = check_stack.build_call_graph(repo)
    depth, path, warnings = check_stack.worst_case_path(graph, "_reset")
    assert any("recursion" in w for w in warnings), warnings


def test_unknown_callee_is_warning(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "_reset", "module": "boot", "stack": "0",
             "body": "        call _ghost\n        ret"},
        ],
    )
    graph = check_stack.build_call_graph(repo)
    depth, path, warnings = check_stack.worst_case_path(graph, "_reset")
    assert any("_ghost" in w for w in warnings), warnings


def test_orphan_detection(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "_reset", "module": "boot", "stack": "0",
             "body": "        ret"},
            {"name": "_dead", "module": "boot", "stack": "64",
             "body": "        ret"},
        ],
    )
    graph = check_stack.build_call_graph(repo)
    reach = check_stack.reachable(graph, "_reset")
    orphans = sorted(set(graph) - reach)
    assert orphans == ["_dead"]


def test_real_repo_under_limit() -> None:
    """The committed binary's deepest reachable stack must fit STACK_SIZE."""
    graph = check_stack.build_call_graph(REPO_ROOT)
    depth, path, _ = check_stack.worst_case_path(graph, "_reset")
    limit = check_stack.stack_size_from_config(REPO_ROOT)
    assert limit is not None
    assert depth <= limit, (
        f"deepest path {' → '.join(path)} = {depth} bytes exceeds limit {limit}"
    )
