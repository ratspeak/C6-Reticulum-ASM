#!/usr/bin/env python3
"""Finite contract/source-shape proof for transport_process_packet."""

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
    pattern = r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*$"
    for path in paths:
        for line in read(path).splitlines():
            m = re.match(pattern, line)
            if m:
                values[m.group(1)] = int(m.group(2), 0)
    return values


EQU = parse_equ("src/include/packet.S", "src/include/transport.S")


def process_model(raw_ptr_nonzero: bool, parse_ok: bool, packet_type: int, delegated_status: int) -> int:
    if not raw_ptr_nonzero or not parse_ok:
        return EQU["TRANSPORT_ERR_INVAL"]
    if packet_type == EQU["PKT_ANNOUNCE"]:
        return delegated_status
    return delegated_status


def prove_constants() -> None:
    require(EQU["PKT_DATA"] == 0, "data packet type")
    require(EQU["PKT_ANNOUNCE"] == 1, "announce packet type")
    require(EQU["PKT_LINKREQUEST"] == 2, "link request packet type")
    require(EQU["TRANSPORT_STATUS_DUPLICATE"] == 2, "transport duplicate status")
    require(EQU["TRANSPORT_STATUS_FORWARDED"] == 3, "transport forwarded status")
    require(EQU["TRANSPORT_ERR_INVAL"] == -1, "transport invalid status")


def prove_finite_model() -> None:
    require(
        process_model(False, True, EQU["PKT_ANNOUNCE"], EQU["TRANSPORT_OK"])
        == EQU["TRANSPORT_ERR_INVAL"],
        "null raw rejected",
    )
    require(
        process_model(True, False, EQU["PKT_ANNOUNCE"], EQU["TRANSPORT_OK"])
        == EQU["TRANSPORT_ERR_INVAL"],
        "parse failure rejected",
    )
    require(
        process_model(True, True, EQU["PKT_ANNOUNCE"], EQU["TRANSPORT_STATUS_UPDATED"])
        == EQU["TRANSPORT_STATUS_UPDATED"],
        "announce status preserved",
    )
    require(
        process_model(True, True, EQU["PKT_LINKREQUEST"], 7) == 7,
        "non-announce delegated status preserved",
    )


def body(path: str, symbol: str) -> str:
    text = read(path)
    m = re.search(
        rf"^\s*{re.escape(symbol)}:\n(?P<body>.*?)(?=^\s*\.size\s+{re.escape(symbol)},)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    require(m is not None, f"{symbol} body missing")
    return m.group("body")


def require_patterns(text: str, patterns: list[str]) -> None:
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"missing {pattern!r}")


def prove_source_shape() -> None:
    src = body("src/transport/transport_process_packet.S", "transport_process_packet")
    require(src.count("call    packet_parse_header") == 1, "packet_parse_header call count")
    require(src.count("call    transport_packet_seen") == 1, "packet hash check call count")
    require(src.count("call    transport_path_lookup") == 1, "path lookup call count")
    require(src.count("call    lora_interface_send") == 4, "LoRa send call count")
    require(src.count("call    transport_process_announce") == 1, "announce dispatch call count")
    require(src.count("call    link_process_packet") == 1, "non-announce delegate call count")
    require_patterns(src, [
        r"\bbeqz\s+s0,\s*\.Ltpp_invalid",
        r"\bTRANSPORT_STATUS_DUPLICATE\b",
        r"\bIDENTITY_OFF_HASH\b",
        r"\bTRANSPORT_INTERFACE_LORA\b",
        r"\bTRANSPORT_PATH_OFF_HOPS\b",
        r"\bTRANSPORT_PATH_OFF_NEXT_HOP\b",
        r"\bTRANSPORT_STATUS_FORWARDED\b",
        r"\bSX1262_BENCH_PAYLOAD_MAX - HASH_LEN\b",
        r"\bSX1262_BENCH_PAYLOAD_MAX\b",
        r"\bANNOUNCE_H2_RAW_OFF_TRANSPORT_ID\b",
        r"\bFLAG_HEADER_TYPE \| FLAG_TRANSPORT\b",
        r"\bbnez\s+a0,\s*\.Ltpp_invalid",
        r"\bPKT_OFF_PACKET_TYPE\b",
        r"\bPKT_ANNOUNCE\b",
        r"\bTRANSPORT_ERR_INVAL\b",
        r"\bsw\s+ra,\s*TPP_RA_OFF\(sp\)",
        r"\blw\s+ra,\s*TPP_RA_OFF\(sp\)",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
