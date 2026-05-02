"""Tests for src/log/log_init.S — placeholder body, single ret today."""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "log_init") > 0


def test_body_is_just_return(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_init")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    assert len(instrs) == 1
    assert "ret" in instrs[0] or "jalr\tzero" in instrs[0]


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="log_init")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"log_init writes callee-saved {match}: {body}")
