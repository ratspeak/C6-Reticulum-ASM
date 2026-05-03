#!/usr/bin/env python3
"""Finite contract/source-shape proof for SX1262 command wrappers."""

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
SPI = parse_equ("src/include/spi.S")
GPIO = parse_equ("src/include/gpio.S")

OK = LORA["LORA_OK"]
ERR_GPIO = LORA["LORA_ERR_GPIO"]
ERR_BUSY_TIMEOUT = LORA["LORA_ERR_BUSY_TIMEOUT"]
ERR_INVAL = LORA["LORA_ERR_INVAL"]
ERR_SPI_TIMEOUT = LORA["LORA_ERR_SPI_TIMEOUT"]
ERR_SPI = LORA["LORA_ERR_SPI"]
SPI_TIMEOUT = SPI["SPI_ERR_TIMEOUT"]
MAX_TRANSFER = SPI["SPI_MAX_TRANSFER"]
NSS = GPIO["GPIO_LORA_NSS_PIN"]
BUSY = GPIO["GPIO_LORA_BUSY_PIN"]


def wait_busy_model(busy_sequence: list[int], timeout: int) -> int:
    if timeout == 0:
        timeout = LORA["SX1262_COMMAND_TIMEOUT_DEFAULT"]
    for busy in busy_sequence:
        if busy < 0:
            return ERR_GPIO
        if busy == 0:
            return OK
        if timeout == 0:
            return ERR_BUSY_TIMEOUT
        timeout -= 1
    return ERR_BUSY_TIMEOUT


def command_write_model(
    opcode: int,
    payload_len: int,
    has_payload: bool,
    busy_sequence: list[int],
    spi_status: int,
) -> tuple[int, int, int]:
    if opcode > 0xFF or payload_len > MAX_TRANSFER - 1:
        return ERR_INVAL, 0, 0
    if payload_len and not has_payload:
        return ERR_INVAL, 0, 0
    busy_status = wait_busy_model(busy_sequence, 3)
    if busy_status != OK:
        return busy_status, 0, 1 << NSS
    total = payload_len + 1
    if spi_status == OK:
        return OK, total, 1 << NSS
    if spi_status == SPI_TIMEOUT:
        return ERR_SPI_TIMEOUT, total, 1 << NSS
    return ERR_SPI, total, 1 << NSS


def command_read_model(
    opcode: int,
    request_len: int,
    has_request: bool,
    rx_len: int,
    has_rx: bool,
    busy_sequence: list[int],
    spi_status: int,
) -> tuple[int, int, int]:
    if opcode > 0xFF or request_len > MAX_TRANSFER or rx_len > MAX_TRANSFER:
        return ERR_INVAL, 0, 0
    if rx_len == 0 or not has_rx:
        return ERR_INVAL, 0, 0
    if request_len and not has_request:
        return ERR_INVAL, 0, 0
    total = 1 + request_len + rx_len
    if total > MAX_TRANSFER:
        return ERR_INVAL, 0, 0
    busy_status = wait_busy_model(busy_sequence, 3)
    if busy_status != OK:
        return busy_status, 0, 1 << NSS
    if spi_status == OK:
        return OK, total, 1 << NSS
    if spi_status == SPI_TIMEOUT:
        return ERR_SPI_TIMEOUT, total, 1 << NSS
    return ERR_SPI, total, 1 << NSS


def prove_constants() -> None:
    require((OK, ERR_GPIO, ERR_BUSY_TIMEOUT, ERR_INVAL) == (0, -1, -2, -3), "status prefix mismatch")
    require(ERR_SPI_TIMEOUT == -4 and ERR_SPI == -5, "SPI status mapping mismatch")
    require(MAX_TRANSFER == 256, "command wrappers must share SPI transfer cap")
    require(NSS == 0 and BUSY == 6, "NSS/BUSY pin contract mismatch")
    require(LORA["SX1262_COMMAND_TIMEOUT_DEFAULT"] >= 1000, "command timeout default too small")


def prove_finite_models() -> None:
    require(command_write_model(0x8A, 3, True, [0], OK) == (OK, 4, 1 << NSS), "write success model")
    require(command_write_model(0x100, 0, False, [0], OK)[0] == ERR_INVAL, "write opcode bound")
    require(command_write_model(0x8A, 256, True, [0], OK)[0] == ERR_INVAL, "write length bound")
    require(command_write_model(0x8A, 1, False, [0], OK)[0] == ERR_INVAL, "write null payload")
    require(command_write_model(0x80, 0, False, [1, 1, 1], OK)[0] == ERR_BUSY_TIMEOUT, "write busy timeout")
    require(command_write_model(0x80, 0, False, [0], SPI_TIMEOUT)[0] == ERR_SPI_TIMEOUT, "write SPI timeout")

    require(command_read_model(0x1D, 2, True, 2, True, [0], OK) == (OK, 5, 1 << NSS), "read success model")
    require(command_read_model(0x1D, 2, True, 254, True, [0], OK)[0] == ERR_INVAL, "read total bound")
    require(command_read_model(0x1D, 0, False, 0, True, [0], OK)[0] == ERR_INVAL, "read zero response")
    require(command_read_model(0x1D, 1, False, 1, True, [0], OK)[0] == ERR_INVAL, "read null request")
    require(command_read_model(0x1D, 0, False, 1, False, [0], OK)[0] == ERR_INVAL, "read null response")
    require(command_read_model(0x1D, 0, False, 1, True, [0], SPI_TIMEOUT)[0] == ERR_SPI_TIMEOUT, "read SPI timeout")


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    common = [
        r"gpio_config_output",
        r"gpio_config_input",
        r"gpio_write",
        r"gpio_read",
        r"clock_delay_us",
        r"spi_transfer",
        r"GPIO_LORA_NSS_PIN",
        r"GPIO_LORA_BUSY_PIN",
        r"SX1262_COMMAND_TIMEOUT_DEFAULT",
        r"SX1262_BUSY_POLL_DELAY_US",
        r"LORA_ERR_BUSY_TIMEOUT",
        r"LORA_ERR_SPI_TIMEOUT",
    ]
    require_patterns("src/interface/lora/sx1262_command_write.S", common + [
        r"sx1262_command_tx_buf",
        r"SPI_MAX_TRANSFER - 1",
        r"addi\s+a2,\s*s2,\s*1",
    ])
    require_patterns("src/interface/lora/sx1262_command_read.S", common + [
        r"sx1262_command_tx_buf",
        r"sx1262_command_rx_buf",
        r"add\s+s8,\s*s8,\s*s4",
        r"sb\s+zero",
    ])
    require_patterns("src/state/lora.S", [
        r"sx1262_command_tx_buf",
        r"sx1262_command_rx_buf",
        r"\.skip\s+SPI_MAX_TRANSFER",
    ])


def main() -> None:
    prove_constants()
    prove_finite_models()
    prove_source_shape()


if __name__ == "__main__":
    main()
