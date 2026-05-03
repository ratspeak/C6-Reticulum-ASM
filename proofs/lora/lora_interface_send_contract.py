#!/usr/bin/env python3
"""Finite contract/source-shape proof for lora_interface_send."""

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


def send_model(interface_ready: bool, sx1262_status: int, packet_len: int) -> tuple[int, int, int]:
    if not interface_ready:
        return LORA["LORA_ERR_NOT_INITIALIZED"], LORA["LORA_ERR_NOT_INITIALIZED"], 0
    if sx1262_status != LORA["LORA_OK"]:
        return sx1262_status, sx1262_status, 0
    return LORA["LORA_OK"], LORA["LORA_OK"], packet_len


def prove_constants() -> None:
    require(LORA["LORA_OK"] == 0, "success status mismatch")
    require(LORA["LORA_ERR_INVAL"] == -3, "invalid status mismatch")
    require(LORA["LORA_ERR_OVERFLOW"] == -6, "overflow status mismatch")
    require(LORA["LORA_ERR_TX_TIMEOUT"] == -7, "TX-timeout status mismatch")
    require(LORA["LORA_ERR_NOT_INITIALIZED"] == -10, "not-initialized status mismatch")


def prove_finite_model() -> None:
    require(send_model(True, LORA["LORA_OK"], 3) == (LORA["LORA_OK"], LORA["LORA_OK"], 3), "success model")
    require(
        send_model(False, LORA["LORA_OK"], 3)
        == (LORA["LORA_ERR_NOT_INITIALIZED"], LORA["LORA_ERR_NOT_INITIALIZED"], 0),
        "interface init guard",
    )
    require(
        send_model(True, LORA["LORA_ERR_INVAL"], 3) == (LORA["LORA_ERR_INVAL"], LORA["LORA_ERR_INVAL"], 0),
        "delegated invalid model",
    )
    require(
        send_model(True, LORA["LORA_ERR_OVERFLOW"], 254)
        == (LORA["LORA_ERR_OVERFLOW"], LORA["LORA_ERR_OVERFLOW"], 0),
        "delegated overflow model",
    )
    require(
        send_model(True, LORA["LORA_ERR_TX_TIMEOUT"], 3)
        == (LORA["LORA_ERR_TX_TIMEOUT"], LORA["LORA_ERR_TX_TIMEOUT"], 0),
        "delegated timeout model",
    )


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    src = read("src/interface/lora/lora_interface_send.S")
    require(src.count("call    sx1262_send_frame") == 1, "must call sx1262_send_frame once")
    require_patterns("src/interface/lora/lora_interface_send.S", [
        r"lora_interface_initialized",
        r"lora_interface_last_status",
        r"lora_interface_tx_len",
        r"sx1262_send_frame",
        r"LORA_ERR_NOT_INITIALIZED",
    ])
    require_patterns("src/state/lora.S", [
        r"lora_interface_initialized",
        r"lora_interface_last_status",
        r"lora_interface_tx_len",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
