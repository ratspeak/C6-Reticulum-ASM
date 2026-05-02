"""End-to-end test for tests/harness/verify.py.

Builds a tiny synthetic repo (FUNCTIONS.md + one .S + one trivial pytest
file) and runs the dispatcher against it. The synthetic .S has @verify:
kat-only so we don't need any external verifier installed.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from harness import verify

SPEC = """\
;; ============================================================================
;; @function:    smoke
;; @module:      smoke
;; @inputs:      a0 = unused
;; @outputs:     a0 = 0
;; @clobbers:    —
;; @preserves:   —
;; @stack:       0
;; @cycles:      4
;; @ct:          not-required
;; @spec:        none
;; @verify:      kat-only; harness-self-test
;; @tests:       tests/smoke/test_smoke.py
;; @adrs:        0001
;; @status:      tested
;; ============================================================================
        .global smoke
smoke:  li a0, 0
        ret
"""

PYTEST_BODY = """\
def test_pass():
    assert True
"""

PYTEST_FAIL_BODY = """\
def test_fail():
    assert False, 'forced'
"""


def _build_repo(root: Path, *, test_body: str = PYTEST_BODY) -> None:
    (root / "src" / "smoke").mkdir(parents=True)
    (root / "src" / "smoke" / "smoke.S").write_text(SPEC, encoding="utf-8")
    (root / "tests" / "smoke").mkdir(parents=True)
    (root / "tests" / "smoke" / "test_smoke.py").write_text(test_body, encoding="utf-8")
    (root / "docs" / "adr").mkdir(parents=True)
    (root / "docs" / "adr" / "0001-fake.md").write_text(
        "# ADR-0001\n\n- **Status:** Accepted\n", encoding="utf-8"
    )
    (root / "FUNCTIONS.md").write_text(
        textwrap.dedent(
            """\
            ## Module: `smoke`

            | Function | Status | Depends-on | ADRs | Spec |
            |----------|--------|-----------|------|------|
            | `smoke` | ◑ tested | — | 0001 | (spec) |
            """
        ),
        encoding="utf-8",
    )


def test_dispatch_passes_for_kat_only_function(tmp_path: Path) -> None:
    _build_repo(tmp_path)
    src_index = verify._source_index(tmp_path)
    result = verify._verify_function("smoke", tmp_path, src_index)
    assert result.overall == "pass", [(s.name, s.status, s.detail) for s in result.steps]
    statuses = {s.name: s.status for s in result.steps}
    assert statuses == {"spec-validate": "pass", "tests": "pass", "verify": "pass"}


def test_dispatch_fails_when_tests_fail(tmp_path: Path) -> None:
    _build_repo(tmp_path, test_body=PYTEST_FAIL_BODY)
    src_index = verify._source_index(tmp_path)
    result = verify._verify_function("smoke", tmp_path, src_index)
    assert result.overall == "fail"
    test_step = next(s for s in result.steps if s.name == "tests")
    assert test_step.status == "fail"


def test_dispatch_skips_when_source_missing(tmp_path: Path) -> None:
    src_index = verify._source_index(tmp_path)
    result = verify._verify_function("nonexistent", tmp_path, src_index)
    assert result.overall == "skip"


def test_dispatch_fails_on_spec_block_error(tmp_path: Path) -> None:
    _build_repo(tmp_path)
    bad = SPEC.replace("@function:    smoke", "@function:    wrongname")
    (tmp_path / "src" / "smoke" / "smoke.S").write_text(bad, encoding="utf-8")
    src_index = verify._source_index(tmp_path)
    result = verify._verify_function("smoke", tmp_path, src_index)
    assert result.overall == "fail"
    assert result.steps[0].name == "spec-validate"
    assert result.steps[0].status == "fail"
