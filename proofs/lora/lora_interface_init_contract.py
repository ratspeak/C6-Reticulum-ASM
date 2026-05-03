#!/usr/bin/env python3
"""Finite contract/source-shape proof for lora_interface_init."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class ProofError(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


def read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def parse_equ(path: str) -> dict[str, int]:
    values: dict[str, int] = {}
    pattern = r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*$"
    for line in read(path).splitlines():
        m = re.match(pattern, line)
        if m:
            values[m.group(1)] = int(m.group(2), 0)
    return values


LORA = parse_equ("src/include/lora.S")


def init_model(sx1262_status: int) -> tuple[int, int, int]:
    if sx1262_status == LORA["LORA_OK"]:
        return LORA["LORA_OK"], 1, LORA["LORA_OK"]
    return sx1262_status, 0, sx1262_status


def prove_constants() -> None:
    require(LORA["LORA_OK"] == 0, "success status mismatch")
    require(LORA["LORA_ERR_BUSY_TIMEOUT"] == -2, "busy-timeout status mismatch")
    require(LORA["LORA_ERR_SPI_TIMEOUT"] == -4, "SPI-timeout status mismatch")


def prove_finite_model() -> None:
    require(init_model(LORA["LORA_OK"]) == (LORA["LORA_OK"], 1, LORA["LORA_OK"]), "success model")
    require(
        init_model(LORA["LORA_ERR_BUSY_TIMEOUT"])
        == (LORA["LORA_ERR_BUSY_TIMEOUT"], 0, LORA["LORA_ERR_BUSY_TIMEOUT"]),
        "busy error model",
    )
    require(
        init_model(LORA["LORA_ERR_SPI_TIMEOUT"])
        == (LORA["LORA_ERR_SPI_TIMEOUT"], 0, LORA["LORA_ERR_SPI_TIMEOUT"]),
        "SPI error model",
    )


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    require_patterns("src/interface/lora/lora_interface_init.S", [
        r"\bcall\s+sx1262_init\b",
        r"\bbnez\s+a0,\s*\.Llora_interface_init_return\b",
        r"lora_interface_initialized",
        r"lora_interface_last_status",
    ])
    require_patterns("src/state/lora.S", [
        r"lora_interface_initialized",
        r"lora_interface_last_status",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
