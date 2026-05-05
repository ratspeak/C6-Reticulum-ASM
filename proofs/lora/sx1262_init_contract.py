#!/usr/bin/env python3
"""Finite contract/source-shape proof for sx1262_init."""

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
GPIO = parse_equ("src/include/gpio.S")


def prove_profile_constants() -> None:
    freq = LORA["SX1262_BENCH_FREQUENCY_HZ"]
    expected_word = (freq * (1 << 25)) // 32_000_000
    require(freq == 915_000_000, "bench frequency must use US915 static profile")
    require(LORA["SX1262_BENCH_RF_FREQ_WORD"] == expected_word, "RF frequency word mismatch")
    require(LORA["SX1262_BENCH_TX_POWER_DBM"] == 7, "bench TX power mismatch")
    require(LORA["SX1262_BENCH_PREAMBLE_SYMBOLS"] == 12, "bench preamble mismatch")
    require(LORA["SX1262_BENCH_PAYLOAD_MAX"] == 253, "bench payload cap mismatch")
    require(LORA["SX1262_LORA_SF8"] == 8, "spreading factor mismatch")
    require(LORA["SX1262_LORA_BW_125_KHZ"] == 4, "SX1262 125 kHz bandwidth enum mismatch")
    require(LORA["SX1262_LORA_CR_4_5"] == 1, "SX1262 CR 4/5 enum mismatch")
    require(LORA["SX1262_IRQ_MASK_BENCH"] == 0x0263, "bench IRQ mask mismatch")


def prove_opcode_constants() -> None:
    expected = {
        "SX1262_CMD_CLEAR_IRQ_STATUS": 0x02,
        "SX1262_CMD_SET_DIO_IRQ_PARAMS": 0x08,
        "SX1262_CMD_SET_STANDBY": 0x80,
        "SX1262_CMD_SET_RF_FREQUENCY": 0x86,
        "SX1262_CMD_SET_PACKET_TYPE": 0x8A,
        "SX1262_CMD_SET_MOD_PARAMS": 0x8B,
        "SX1262_CMD_SET_PACKET_PARAMS": 0x8C,
        "SX1262_CMD_SET_BUFFER_BASE": 0x8F,
        "SX1262_CMD_SET_TX_PARAMS": 0x8E,
        "SX1262_CMD_GET_STATUS": 0xC0,
    }
    for name, value in expected.items():
        require(LORA[name] == value, f"{name} opcode mismatch")


def init_model(busy_low: bool, command_statuses: list[int]) -> tuple[int, int, int]:
    if not busy_low:
        return LORA["LORA_ERR_BUSY_TIMEOUT"], 0, 0
    require(len(command_statuses) == 15, "model command count must stay fixed")
    for status in command_statuses:
        if status != LORA["LORA_OK"]:
            return status, 0, 0
    return LORA["LORA_OK"], 1, 15


def prove_finite_model() -> None:
    ok = LORA["LORA_OK"]
    require(init_model(True, [ok] * 15) == (ok, 1, 15), "success init model")
    require(init_model(False, [ok] * 15)[0] == LORA["LORA_ERR_BUSY_TIMEOUT"], "busy timeout model")
    command_error = LORA["LORA_ERR_SPI_TIMEOUT"]
    rc, initialized, transfers = init_model(True, [ok] * 7 + [command_error] + [ok] * 7)
    require((rc, initialized, transfers) == (command_error, 0, 0), "command error model")


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    src = read("src/interface/lora/sx1262_init.S")
    require(len(re.findall(r"^\s+SX1262_INIT_WRITE\b", src, re.MULTILINE)) == 14, "init must issue 14 write commands")
    require_patterns("src/interface/lora/sx1262_init.S", [
        r"spi_init",
        r"sx1262_reset",
        r"gpio_config_input",
        r"GPIO_LORA_DIO1_PIN",
        r"sx1262_command_write",
        r"sx1262_command_read",
        r"sx1262_model_initialized",
        r"sx1262_model_init_error",
        r"sx1262_model_status_byte",
        r"SX1262_CMD_SET_STANDBY",
        r"SX1262_CMD_SET_RF_FREQUENCY",
        r"SX1262_CMD_SET_DIO_IRQ_PARAMS",
        r"SX1262_CMD_GET_STATUS",
        r"SX1262_IMAGE_CAL_902_928_1",
        r"SX1262_IMAGE_CAL_902_928_2",
        r"SX1262_BENCH_RF_FREQ_WORD\s*>>\s*24",
        r"SX1262_BENCH_RF_FREQ_WORD\s*>>\s*16",
        r"SX1262_BENCH_RF_FREQ_WORD\s*>>\s*8",
        r"SX1262_LORA_SF8",
        r"SX1262_LORA_BW_125_KHZ",
        r"SX1262_LORA_CR_4_5",
        r"SX1262_BENCH_PAYLOAD_MAX",
        r"0x02,\s*0x63,\s*0x02,\s*0x63",
    ])
    require_patterns("src/state/lora.S", [
        r"sx1262_model_initialized",
        r"sx1262_model_init_error",
        r"sx1262_model_status_byte",
    ])
    require(GPIO["GPIO_LORA_DIO1_PIN"] == 5, "DIO1 pin contract mismatch")


def main() -> None:
    prove_profile_constants()
    prove_opcode_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
