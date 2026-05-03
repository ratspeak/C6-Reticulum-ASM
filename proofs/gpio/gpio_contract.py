#!/usr/bin/env python3
"""Finite contract/source-shape proof for milestone-8 GPIO helpers."""

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


GPIO = parse_equ("src/include/gpio.S")
OK = GPIO["GPIO_OK"]
ERR = GPIO["GPIO_ERR_INVAL"]
OUTPUT_MASK = GPIO["GPIO_LORA_OUTPUT_MASK"]
INPUT_MASK = GPIO["GPIO_LORA_INPUT_MASK"]
ALLOWED_MASK = GPIO["GPIO_LORA_ALLOWED_MASK"]
PIN_LIMIT = GPIO["GPIO_PIN_LIMIT"]


def bit(pin: int) -> int:
    return 1 << pin


def output_allowed(pin: int) -> bool:
    return 0 <= pin < PIN_LIMIT and (OUTPUT_MASK & bit(pin)) != 0


def input_allowed(pin: int) -> bool:
    return 0 <= pin < PIN_LIMIT and (INPUT_MASK & bit(pin)) != 0


def config_output(pin: int, configured: int, direction: int) -> tuple[int, int, int]:
    if not output_allowed(pin):
        return ERR, configured, direction
    mask = bit(pin)
    return OK, configured | mask, direction | mask


def config_input(pin: int, configured: int, direction: int) -> tuple[int, int, int]:
    if not input_allowed(pin):
        return ERR, configured, direction
    mask = bit(pin)
    return OK, configured | mask, direction & ~mask


def write(pin: int, level_value: int, configured: int, direction: int, level: int) -> tuple[int, int]:
    if level_value not in (0, 1) or not output_allowed(pin):
        return ERR, level
    mask = bit(pin)
    if (configured & mask) == 0 or (direction & mask) == 0:
        return ERR, level
    return OK, (level | mask) if level_value else (level & ~mask)


def read_pin(pin: int, configured: int, direction: int, level: int) -> int:
    if not input_allowed(pin):
        return ERR
    mask = bit(pin)
    if (configured & mask) == 0 or (direction & mask) != 0:
        return ERR
    return 1 if (level & mask) else 0


def source(path: str) -> str:
    return read(path)


def require_patterns(path: str, patterns: list[str]) -> None:
    text = source(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_masks() -> None:
    require(OK == 0 and ERR < 0, "return code contract")
    require(PIN_LIMIT == 31, "C6 public GPIO range must be 0..30")
    require(OUTPUT_MASK == bit(0) | bit(7), "output mask must be NSS+NRST")
    require(INPUT_MASK == bit(5) | bit(6), "input mask must be DIO1+BUSY")
    require(ALLOWED_MASK == OUTPUT_MASK | INPUT_MASK, "allowed mask mismatch")

    for pin in range(0, 31):
        if pin in (0, 7):
            require(output_allowed(pin), f"output pin {pin} rejected")
            require(not input_allowed(pin), f"output pin {pin} accepted as input")
        elif pin in (5, 6):
            require(input_allowed(pin), f"input pin {pin} rejected")
            require(not output_allowed(pin), f"input pin {pin} accepted as output")
        else:
            require(not output_allowed(pin), f"unexpected output pin {pin}")
            require(not input_allowed(pin), f"unexpected input pin {pin}")


def prove_finite_model() -> None:
    configured = direction = level = 0

    rc, configured, direction = config_output(0, configured, direction)
    require((rc, configured, direction) == (OK, bit(0), bit(0)), "NSS output config")
    rc, level = write(0, 1, configured, direction, level)
    require(rc == OK and level == bit(0), "NSS write high")
    rc, level = write(0, 0, configured, direction, level)
    require(rc == OK and level == 0, "NSS write low")

    rc, configured, direction = config_input(6, configured, direction)
    require(rc == OK and configured == (bit(0) | bit(6)), "BUSY input config")
    require(read_pin(6, configured, direction, bit(6)) == 1, "BUSY high read")
    require(read_pin(6, configured, direction, 0) == 0, "BUSY low read")

    for pin in (-1, 1, 4, 8, 12, 15, 21, 31):
        require(config_output(pin, 0, 0)[0] == ERR, f"invalid output pin {pin}")
        require(config_input(pin, 0, 0)[0] == ERR, f"invalid input pin {pin}")
        require(write(pin, 1, 0, 0, 0)[0] == ERR, f"invalid write pin {pin}")
        require(read_pin(pin, 0, 0, 0) == ERR, f"invalid read pin {pin}")

    require(write(7, 2, bit(7), bit(7), 0)[0] == ERR, "non-binary write accepted")
    require(write(7, 1, 0, 0, 0)[0] == ERR, "unconfigured write accepted")
    require(read_pin(5, 0, 0, 0) == ERR, "unconfigured read accepted")


def prove_source_shape() -> None:
    common_validate = [
        r"GPIO_PIN_LIMIT",
        r"GPIO_LORA_",
        r"gpio_model_configured",
        r"gpio_model_direction",
    ]
    require_patterns("src/interface/gpio/gpio_config_output.S", common_validate + [
        r"C6_GPIO_ENABLE_W1TS",
        r"C6_GPIO_FUNC_OUT_SEL_BASE",
    ])
    require_patterns("src/interface/gpio/gpio_config_input.S", common_validate + [
        r"C6_GPIO_ENABLE_W1TC",
        r"C6_IO_MUX_GPIO_FUNC_IE",
    ])
    require_patterns("src/interface/gpio/gpio_write.S", common_validate + [
        r"gpio_model_level",
        r"C6_GPIO_OUT_W1TS",
        r"C6_GPIO_OUT_W1TC",
    ])
    require_patterns("src/interface/gpio/gpio_read.S", common_validate + [
        r"gpio_model_level",
        r"C6_GPIO_IN",
        r"snez\s+a0",
    ])


def main() -> None:
    prove_masks()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
