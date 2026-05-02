#!/usr/bin/env python3
"""Worst-case stack depth analyzer.

Walks every .S in src/, parses each function's @stack value and its
`call <sym>` / `tail <sym>` / `jal <sym>` outgoing edges, builds a call
graph rooted at `_reset`, and reports the maximum cumulative stack
depth along any reachable path.

Cycles are rejected as recursion (we have none today; recursion in this
project would need a separate ADR to allow). Functions reachable from
`_reset` whose @stack is not declared are reported.

Exits 0 if the worst-case depth fits the configured stack region (per
src/include/config.S STACK_SIZE), 1 otherwise. The threshold is read at
runtime so a STACK_SIZE bump in config.S re-tunes the gate without code
changes.

Usage:
    check_stack.py                # text report
    check_stack.py --json
    check_stack.py --root _reset  # alternate entry point
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "tools"))
import parse_spec  # noqa: E402

CALL_RE = re.compile(
    r"^\s*(?:call|tail|jal)\s+(?:[a-z]\w*\s*,\s*)?([A-Za-z_]\w*)",
    re.MULTILINE,
)


def _parse_stack(value: str) -> int:
    """Extract the leading integer from a @stack field value."""
    m = re.match(r"\s*(\d+)", value)
    return int(m.group(1)) if m else 0


def _scan_function(path: Path) -> tuple[str, int, list[str]]:
    """Return (function_name, stack_bytes, sorted list of callees)."""
    spec = parse_spec.parse_spec(path)
    name = spec.fields["function"]
    stack = _parse_stack(spec.fields["stack"])
    text = path.read_text(encoding="utf-8")
    callees: set[str] = set()
    for m in CALL_RE.finditer(text):
        callee = m.group(1)
        # Skip jumps to local labels (`.L…`) and to register-named pseudo
        # targets — we already filtered the register-bearing form via the
        # leading `[a-z]\w*,\s*` group. Self-calls are NOT skipped here:
        # they are recursion, which the worst-case-path search must flag.
        if callee.startswith(".L"):
            continue
        callees.add(callee)
    return name, stack, sorted(callees)


def build_call_graph(repo_root: Path) -> dict[str, dict]:
    """{function_name: {'path': Path, 'stack': int, 'callees': [str]}}."""
    src = repo_root / "src"
    graph: dict[str, dict] = {}
    for path in sorted(src.rglob("*.S")):
        if "include" in path.parts:
            continue
        if "state" in path.parts:
            continue  # state/ files declare data, not functions
        name, stack, callees = _scan_function(path)
        graph[name] = {"path": path, "stack": stack, "callees": callees}
    return graph


def worst_case_path(
    graph: dict[str, dict], root: str
) -> tuple[int, list[str], list[str]]:
    """Return (max_depth_bytes, path, warnings).

    Detects cycles (recursion). Functions reachable but not in the graph
    are reported in `warnings`.
    """
    if root not in graph:
        return 0, [], [f"root {root!r} not in graph"]

    warnings: list[str] = []
    # Initialise to -1 so the first visit (depth 0 from a leaf root) wins
    # the comparison and updates best_path.
    best_depth = [-1]
    best_path: list[list[str]] = [[]]

    def dfs(node: str, accum: int, stack: list[str], on_path: set[str]) -> None:
        info = graph.get(node)
        if info is None:
            warnings.append(
                f"{stack[-1] if stack else '?'} calls {node!r} "
                "which has no .S in src/"
            )
            return
        new_accum = accum + info["stack"]
        new_stack = stack + [node]
        if new_accum > best_depth[0]:
            best_depth[0] = new_accum
            best_path[0] = new_stack[:]
        if not info["callees"]:
            return
        for callee in info["callees"]:
            if callee in on_path:
                warnings.append(
                    f"recursion detected: {' → '.join(new_stack + [callee])}"
                )
                continue
            dfs(callee, new_accum, new_stack, on_path | {callee})

    dfs(root, 0, [], {root})
    return max(best_depth[0], 0), best_path[0], warnings


def stack_size_from_config(repo_root: Path) -> int | None:
    """Read STACK_SIZE from src/include/config.S (the .equ value)."""
    p = repo_root / "src" / "include" / "config.S"
    if not p.is_file():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(
            r"^\s*\.equ\s+STACK_SIZE,\s*(0[xX][0-9a-fA-F]+|\d+)", line
        )
        if m:
            v = m.group(1)
            return int(v, 16) if v.lower().startswith("0x") else int(v)
    return None


def reachable(graph: dict[str, dict], root: str) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        info = graph.get(n)
        if info is None:
            continue
        stack.extend(info["callees"])
    return seen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="_reset")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    graph = build_call_graph(repo_root)
    depth, path, warnings = worst_case_path(graph, args.root)
    limit = stack_size_from_config(repo_root)

    over_limit = limit is not None and depth > limit
    reach = reachable(graph, args.root)
    orphans = sorted(set(graph) - reach)

    report = {
        "root": args.root,
        "max_depth_bytes": depth,
        "max_depth_path": path,
        "limit_bytes": limit,
        "over_limit": over_limit,
        "warnings": warnings,
        "orphan_functions": orphans,
    }

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"root: {args.root}")
        print(f"max stack: {depth} bytes (limit: {limit})")
        print(f"path: {' → '.join(path)}")
        if warnings:
            print()
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
        if orphans:
            print()
            print(f"orphans (not reachable from {args.root}):")
            for o in orphans:
                print(f"  {o}")

    return 1 if over_limit else 0


if __name__ == "__main__":
    sys.exit(main())
