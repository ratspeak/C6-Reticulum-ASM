#!/usr/bin/env python3
"""Finite contract/source-shape proof for sx1262_reset."""

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
    for line in read(path).splitlines():
        m = re.match(r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*$", line)
        if m:
            values[m.group(1)] = int(m.group(2), 0)
    return values


LORA = parse_equ("src/include/lora.S")
GPIO = parse_equ("src/include/gpio.S")

OK = LORA["LORA_OK"]
ERR_GPIO = LORA["LORA_ERR_GPIO"]
ERR_BUSY_TIMEOUT = LORA["LORA_ERR_BUSY_TIMEOUT"]
NRST = GPIO["GPIO_LORA_NRST_PIN"]
BUSY = GPIO["GPIO_LORA_BUSY_PIN"]


def reset_model(busy_sequence: list[int], budget: int) -> tuple[int, int, int, int]:
    if budget == 0:
        budget = LORA["SX1262_BUSY_TIMEOUT_DEFAULT"]

    configured = (1 << NRST) | (1 << BUSY)
    direction = 1 << NRST
    level = 1 << NRST

    reads = 0
    for busy in busy_sequence:
        reads += 1
        if busy < 0:
            return ERR_GPIO, configured, direction, level
        if busy == 0:
            return OK, configured, direction, level
        if budget == 0:
            return ERR_BUSY_TIMEOUT, configured, direction, level | (1 << BUSY)
        budget -= 1
    return ERR_BUSY_TIMEOUT, configured, direction, level | (1 << BUSY)


def prove_constants() -> None:
    require((OK, ERR_GPIO, ERR_BUSY_TIMEOUT) == (0, -1, -2), "status code contract")
    require(NRST == 7 and BUSY == 6, "reset/BUSY pin contract mismatch")
    require(LORA["SX1262_RESET_LOW_US"] >= 100, "reset low pulse too short")
    require(LORA["SX1262_RESET_SETTLE_US"] >= 100, "reset settle delay too short")
    require(LORA["SX1262_BUSY_POLL_DELAY_US"] > 0, "busy poll delay must be positive")
    require(LORA["SX1262_BUSY_TIMEOUT_DEFAULT"] >= 1000, "default busy budget too small")


def prove_finite_model() -> None:
    rc, configured, direction, level = reset_model([0], 3)
    require(rc == OK, "BUSY-low reset rejected")
    require(configured == ((1 << NRST) | (1 << BUSY)), "configured pins mismatch")
    require(direction == (1 << NRST), "direction pins mismatch")
    require(level == (1 << NRST), "NRST not high after reset")

    rc, _, _, level = reset_model([1, 1, 1], 2)
    require(rc == ERR_BUSY_TIMEOUT, "BUSY-high timeout not reported")
    require(level == ((1 << NRST) | (1 << BUSY)), "timeout level model mismatch")

    require(reset_model([0], 0)[0] == OK, "default budget rejected")
    require(reset_model([-1], 3)[0] == ERR_GPIO, "GPIO read error not propagated")


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    require_patterns("src/interface/lora/sx1262_reset.S", [
        r"gpio_config_output",
        r"gpio_config_input",
        r"gpio_write",
        r"gpio_read",
        r"clock_delay_us",
        r"GPIO_LORA_NRST_PIN",
        r"GPIO_LORA_BUSY_PIN",
        r"SX1262_RESET_LOW_US",
        r"SX1262_BUSY_TIMEOUT_DEFAULT",
        r"LORA_ERR_BUSY_TIMEOUT",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
