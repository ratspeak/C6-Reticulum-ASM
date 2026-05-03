#!/usr/bin/env python3
"""Finite contract/source-shape proof for sx1262_send_frame."""

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


def send_model(initialized: bool, frame_len: int, irq_sequence: list[int]) -> tuple[int, int, int]:
    if not initialized:
        return LORA["LORA_ERR_NOT_INITIALIZED"], 0, 0
    if frame_len == 0:
        return LORA["LORA_ERR_INVAL"], 0, 0
    if frame_len > LORA["SX1262_BENCH_PAYLOAD_MAX"]:
        return LORA["LORA_ERR_OVERFLOW"], 0, 0
    for irq in irq_sequence:
        if irq & LORA["SX1262_IRQ_TX_DONE"]:
            return LORA["LORA_OK"], frame_len, irq
        if irq & LORA["SX1262_IRQ_TIMEOUT"]:
            return LORA["LORA_ERR_TX_TIMEOUT"], 0, irq
    return LORA["LORA_ERR_TX_TIMEOUT"], 0, 0


def prove_constants() -> None:
    require(LORA["LORA_ERR_OVERFLOW"] == -6, "overflow status mismatch")
    require(LORA["LORA_ERR_TX_TIMEOUT"] == -7, "TX timeout status mismatch")
    require(LORA["LORA_ERR_NOT_INITIALIZED"] == -10, "not-initialized status mismatch")
    require(LORA["SX1262_CMD_WRITE_BUFFER"] == 0x0E, "WriteBuffer opcode mismatch")
    require(LORA["SX1262_CMD_SET_TX"] == 0x83, "SetTx opcode mismatch")
    require(LORA["SX1262_CMD_GET_IRQ_STATUS"] == 0x12, "GetIrqStatus opcode mismatch")
    require(
        LORA["SX1262_BENCH_PAYLOAD_MAX"] == SPI["SPI_MAX_TRANSFER"] - 3,
        "shared TX/RX cap must fit opcode+offset+dummy ReadBuffer path",
    )
    require(LORA["SX1262_IRQ_TX_DONE"] == 0x0001, "TX done IRQ mismatch")
    require(LORA["SX1262_IRQ_TIMEOUT"] == 0x0200, "timeout IRQ mismatch")


def prove_finite_model() -> None:
    require(send_model(True, 3, [0x0001]) == (LORA["LORA_OK"], 3, 0x0001), "TX done model")
    require(send_model(False, 3, [0x0001])[0] == LORA["LORA_ERR_NOT_INITIALIZED"], "init guard")
    require(send_model(True, 0, [0x0001])[0] == LORA["LORA_ERR_INVAL"], "zero frame guard")
    require(
        send_model(True, LORA["SX1262_BENCH_PAYLOAD_MAX"] + 1, [0x0001])[0]
        == LORA["LORA_ERR_OVERFLOW"],
        "overflow guard",
    )
    require(send_model(True, 3, [0x0200])[0] == LORA["LORA_ERR_TX_TIMEOUT"], "radio timeout model")
    require(send_model(True, 3, [0, 0])[0] == LORA["LORA_ERR_TX_TIMEOUT"], "poll budget timeout model")


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    require_patterns("src/interface/lora/sx1262_send_frame.S", [
        r"sx1262_model_initialized",
        r"sx1262_frame_tx_buf",
        r"sx1262_tx_packet_params_buf",
        r"sx1262_model_tx_len",
        r"sx1262_model_last_irq",
        r"SX1262_CMD_SET_PACKET_PARAMS",
        r"SX1262_CMD_WRITE_BUFFER",
        r"SX1262_CMD_CLEAR_IRQ_STATUS",
        r"SX1262_CMD_SET_TX",
        r"SX1262_CMD_GET_IRQ_STATUS",
        r"sx1262_command_write",
        r"sx1262_command_read",
        r"clock_delay_us",
        r"SX1262_IRQ_TX_DONE",
        r"SX1262_IRQ_TIMEOUT",
        r"LORA_ERR_NOT_INITIALIZED",
        r"LORA_ERR_OVERFLOW",
        r"LORA_ERR_TX_TIMEOUT",
    ])
    require_patterns("src/state/lora.S", [
        r"sx1262_frame_tx_buf",
        r"sx1262_tx_packet_params_buf",
        r"sx1262_irq_read_buf",
        r"sx1262_model_tx_len",
        r"sx1262_model_last_irq",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
