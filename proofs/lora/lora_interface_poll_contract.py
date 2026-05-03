#!/usr/bin/env python3
"""Finite contract/source-shape proof for lora_interface_poll."""

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


def parse_equ(*paths: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for path in paths:
        pattern = r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*$"
        for line in read(path).splitlines():
            m = re.match(pattern, line)
            if m:
                values[m.group(1)] = int(m.group(2), 0)
    return values


EQU = parse_equ("src/include/lora.S", "src/include/transport.S", "src/include/link.S")


def poll_model(interface_ready: bool, radio_result: int, dispatch_status: int) -> tuple[int, int, int]:
    if not interface_ready:
        return EQU["LORA_ERR_NOT_INITIALIZED"], 0, 0
    if radio_result <= 0:
        return radio_result, 0, 0
    return dispatch_status, radio_result, dispatch_status


def prove_constants() -> None:
    require(EQU["LORA_ERR_NO_PACKET"] == -8, "no-packet status mismatch")
    require(EQU["LORA_ERR_CRC"] == -9, "CRC status mismatch")
    require(EQU["LORA_ERR_NOT_INITIALIZED"] == -10, "not-initialized status mismatch")
    require(EQU["TRANSPORT_INTERFACE_KISS"] == 1, "KISS interface id mismatch")
    require(EQU["TRANSPORT_INTERFACE_LORA"] == 2, "LoRa interface id mismatch")
    require(EQU["LINK_ERR_INVAL"] == -1, "link invalid status mismatch")
    require(EQU["LINK_STATUS_DECRYPTED"] == 2, "link decrypted status mismatch")


def prove_finite_model() -> None:
    require(
        poll_model(False, 2, EQU["LINK_STATUS_DECRYPTED"])
        == (EQU["LORA_ERR_NOT_INITIALIZED"], 0, 0),
        "interface init guard",
    )
    require(
        poll_model(True, EQU["LORA_ERR_NO_PACKET"], EQU["LINK_STATUS_DECRYPTED"])
        == (EQU["LORA_ERR_NO_PACKET"], 0, 0),
        "no packet model",
    )
    require(
        poll_model(True, EQU["LORA_ERR_CRC"], EQU["LINK_STATUS_DECRYPTED"])
        == (EQU["LORA_ERR_CRC"], 0, 0),
        "radio error model",
    )
    require(
        poll_model(True, 2, EQU["LINK_STATUS_DECRYPTED"])
        == (EQU["LINK_STATUS_DECRYPTED"], 2, EQU["LINK_STATUS_DECRYPTED"]),
        "dispatch success model",
    )
    require(
        poll_model(True, 2, EQU["LINK_ERR_INVAL"]) == (EQU["LINK_ERR_INVAL"], 2, EQU["LINK_ERR_INVAL"]),
        "dispatch invalid model",
    )


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    src = read("src/interface/lora/lora_interface_poll.S")
    require(src.count("call    sx1262_poll_receive") == 1, "must call sx1262_poll_receive once")
    require(src.count("call    link_process_packet") == 1, "must call link_process_packet once")
    require_patterns("src/interface/lora/lora_interface_poll.S", [
        r"lora_interface_initialized",
        r"lora_interface_rx_buf",
        r"lora_interface_rx_len",
        r"lora_interface_dispatch_status",
        r"lora_interface_last_status",
        r"SX1262_BENCH_PAYLOAD_MAX",
        r"TRANSPORT_INTERFACE_LORA",
        r"LORA_ERR_NOT_INITIALIZED",
        r"sx1262_poll_receive",
        r"link_process_packet",
    ])
    require_patterns("src/state/lora.S", [
        r"lora_interface_rx_buf",
        r"lora_interface_rx_len",
        r"lora_interface_dispatch_status",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
