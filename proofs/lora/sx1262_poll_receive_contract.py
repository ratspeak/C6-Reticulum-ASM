#!/usr/bin/env python3
"""Finite contract/source-shape proof for sx1262_poll_receive."""

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


def poll_model(
    initialized: bool,
    output_nonnull: bool,
    output_cap: int,
    dio1_high: bool,
    irq: int,
    rx_len: int,
) -> int:
    if not initialized:
        return LORA["LORA_ERR_NOT_INITIALIZED"]
    if not output_nonnull or output_cap == 0:
        return LORA["LORA_ERR_INVAL"]
    if not dio1_high:
        return LORA["LORA_ERR_NO_PACKET"]
    if irq & (LORA["SX1262_IRQ_HEADER_ERR"] | LORA["SX1262_IRQ_CRC_ERR"]):
        return LORA["LORA_ERR_CRC"]
    if irq & LORA["SX1262_IRQ_TIMEOUT"]:
        return LORA["LORA_ERR_NO_PACKET"]
    if not (irq & LORA["SX1262_IRQ_RX_DONE"]):
        return LORA["LORA_ERR_NO_PACKET"]
    if rx_len == 0:
        return LORA["LORA_ERR_NO_PACKET"]
    if rx_len > output_cap or rx_len > LORA["SX1262_BENCH_PAYLOAD_MAX"]:
        return LORA["LORA_ERR_OVERFLOW"]
    return rx_len


def prove_constants() -> None:
    require(LORA["LORA_ERR_INVAL"] == -3, "invalid status mismatch")
    require(LORA["LORA_ERR_OVERFLOW"] == -6, "overflow status mismatch")
    require(LORA["LORA_ERR_NO_PACKET"] == -8, "no-packet status mismatch")
    require(LORA["LORA_ERR_CRC"] == -9, "CRC status mismatch")
    require(LORA["LORA_ERR_NOT_INITIALIZED"] == -10, "not-initialized status mismatch")
    require(LORA["SX1262_CMD_CLEAR_IRQ_STATUS"] == 0x02, "ClearIrqStatus opcode mismatch")
    require(LORA["SX1262_CMD_GET_IRQ_STATUS"] == 0x12, "GetIrqStatus opcode mismatch")
    require(LORA["SX1262_CMD_GET_RX_BUFFER_STATUS"] == 0x13, "GetRxBufferStatus opcode mismatch")
    require(LORA["SX1262_CMD_READ_BUFFER"] == 0x1E, "ReadBuffer opcode mismatch")
    require(LORA["SX1262_CMD_SET_RX"] == 0x82, "SetRx opcode mismatch")
    require(LORA["SX1262_RX_CONTINUOUS_TIMEOUT"] == 0xFFFFFF, "continuous RX timeout mismatch")
    require(
        LORA["SX1262_BENCH_PAYLOAD_MAX"] == SPI["SPI_MAX_TRANSFER"] - 3,
        "RX cap must fit opcode+offset+dummy+payload in one SPI transfer",
    )
    require(LORA["SX1262_IRQ_RX_DONE"] == 0x0002, "RX done IRQ mismatch")
    require(LORA["SX1262_IRQ_HEADER_ERR"] == 0x0020, "header error IRQ mismatch")
    require(LORA["SX1262_IRQ_CRC_ERR"] == 0x0040, "CRC error IRQ mismatch")
    require(LORA["SX1262_IRQ_TIMEOUT"] == 0x0200, "timeout IRQ mismatch")


def prove_finite_model() -> None:
    require(poll_model(True, True, 4, True, 0x0002, 2) == 2, "successful RX model")
    require(
        poll_model(False, True, 4, True, 0x0002, 2) == LORA["LORA_ERR_NOT_INITIALIZED"],
        "init guard",
    )
    require(poll_model(True, False, 4, True, 0x0002, 2) == LORA["LORA_ERR_INVAL"], "null output guard")
    require(poll_model(True, True, 0, True, 0x0002, 2) == LORA["LORA_ERR_INVAL"], "zero cap guard")
    require(poll_model(True, True, 4, False, 0x0002, 2) == LORA["LORA_ERR_NO_PACKET"], "DIO low model")
    require(poll_model(True, True, 4, True, 0x0040, 2) == LORA["LORA_ERR_CRC"], "CRC IRQ model")
    require(poll_model(True, True, 4, True, 0x0200, 2) == LORA["LORA_ERR_NO_PACKET"], "timeout IRQ model")
    require(poll_model(True, True, 4, True, 0x0000, 2) == LORA["LORA_ERR_NO_PACKET"], "missing RX_DONE model")
    require(poll_model(True, True, 4, True, 0x0002, 0) == LORA["LORA_ERR_NO_PACKET"], "empty FIFO model")
    require(poll_model(True, True, 1, True, 0x0002, 2) == LORA["LORA_ERR_OVERFLOW"], "caller cap overflow")
    require(
        poll_model(True, True, 255, True, 0x0002, LORA["SX1262_BENCH_PAYLOAD_MAX"] + 1)
        == LORA["LORA_ERR_OVERFLOW"],
        "driver cap overflow",
    )


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    require_patterns("src/interface/lora/sx1262_poll_receive.S", [
        r"sx1262_model_initialized",
        r"sx1262_model_rx_len",
        r"sx1262_model_rx_armed",
        r"sx1262_model_last_irq",
        r"sx1262_irq_read_buf",
        r"sx1262_rx_status_buf",
        r"sx1262_read_buffer_req_buf",
        r"sx1262_frame_rx_buf",
        r"gpio_config_input",
        r"gpio_read",
        r"sx1262_command_read",
        r"sx1262_command_write",
        r"SX1262_CMD_GET_IRQ_STATUS",
        r"SX1262_CMD_GET_RX_BUFFER_STATUS",
        r"SX1262_CMD_READ_BUFFER",
        r"SX1262_CMD_CLEAR_IRQ_STATUS",
        r"SX1262_CMD_SET_RX",
        r"SX1262_RX_CONTINUOUS_TIMEOUT",
        r"SX1262_IRQ_RX_DONE",
        r"SX1262_IRQ_HEADER_ERR",
        r"SX1262_IRQ_CRC_ERR",
        r"SX1262_IRQ_TIMEOUT",
        r"LORA_ERR_NOT_INITIALIZED",
        r"LORA_ERR_INVAL",
        r"LORA_ERR_OVERFLOW",
        r"LORA_ERR_NO_PACKET",
        r"LORA_ERR_CRC",
    ])
    require_patterns("src/state/lora.S", [
        r"sx1262_frame_rx_buf",
        r"sx1262_rx_status_buf",
        r"sx1262_read_buffer_req_buf",
        r"sx1262_model_rx_len",
        r"sx1262_model_rx_armed",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
