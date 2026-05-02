"""Tests for src/clock/clock_init.S.

On qemu-virt the body is `ret` — the CPU is already running at qemu's
configured rate. The test asserts the function exists, contains exactly
one return, and preserves callee-saved registers (trivially, since the
body is empty).

The C6-target test will assert the post-condition that the CPU is at
160 MHz; that lands when the C6 register sequence does.
"""

from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    addr = build.symbol_address(artifacts.elf, "clock_init")
    assert addr > 0


def test_qemu_virt_body_is_just_return(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_init")
    instrs = [line for line in body.splitlines() if re.match(r"^\s*[0-9a-f]{8}:", line)]
    assert len(instrs) == 1, body
    assert "ret" in instrs[0] or "jalr\tzero" in instrs[0], instrs[0]


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="clock_init")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"clock_init writes callee-saved {match}: {body}")
