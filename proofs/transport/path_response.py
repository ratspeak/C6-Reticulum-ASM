#!/usr/bin/env python3
"""Finite model/source-shape proof for transport path-response helpers."""

from __future__ import annotations

import dataclasses
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
    pending: list[tuple[str, str]] = []
    for path in paths:
        for line in read(path).splitlines():
            m = re.match(r"\s*\.equ\s+([A-Z0-9_]+),\s*(.+?)\s*(?:/\*.*)?$", line)
            if m:
                pending.append((m.group(1), m.group(2).strip()))
    changed = True
    while changed and pending:
        changed = False
        next_pending: list[tuple[str, str]] = []
        for name, expr in pending:
            try:
                safe_expr = re.sub(
                    r"\b[A-Z][A-Z0-9_]*\b",
                    lambda m: str(values[m.group(0)]),
                    expr,
                )
                values[name] = int(eval(safe_expr, {"__builtins__": {}}, {}))
                changed = True
            except (KeyError, NameError, SyntaxError):
                next_pending.append((name, expr))
        pending = next_pending
    return values


EQU = parse_equ("src/include/packet.S", "src/include/announce.S",
                "src/include/lora.S", "src/include/transport.S")


@dataclasses.dataclass
class Response:
    valid: bool = False
    dest_hash: bytes = bytes(16)
    raw: bytes = b""


def h1_response(raw: bytes, hops: int, local_id: bytes) -> bytes:
    require(len(raw) <= EQU["SX1262_BENCH_PAYLOAD_MAX"] - EQU["HASH_LEN"],
            "H1 response fits LoRa payload max")
    out = bytearray()
    out.append(EQU["ANNOUNCE_HEADER2_FLAGS"])
    out.append(hops & 0xFF)
    out += local_id
    out += raw[EQU["ANNOUNCE_RAW_OFF_DEST_HASH"]:]
    out[EQU["ANNOUNCE_H2_RAW_OFF_CONTEXT"]] = EQU["TRANSPORT_CONTEXT_PATH_RESPONSE"]
    return bytes(out)


def h2_response(raw: bytes, hops: int, local_id: bytes) -> bytes:
    require(len(raw) <= EQU["SX1262_BENCH_PAYLOAD_MAX"],
            "H2 response fits LoRa payload max")
    out = bytearray(raw)
    out[0] = EQU["ANNOUNCE_HEADER2_FLAGS"]
    out[1] = hops & 0xFF
    out[EQU["ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID"]:
        EQU["ANNOUNCE_H2_RAW_OFF_TRANSPORT_ID"] + 16] = local_id
    out[EQU["ANNOUNCE_H2_RAW_OFF_CONTEXT"]] = EQU["TRANSPORT_CONTEXT_PATH_RESPONSE"]
    return bytes(out)


def prove_constants() -> None:
    require(EQU["TRANSPORT_CONTEXT_NONE"] == 0, "context none")
    require(EQU["TRANSPORT_CONTEXT_PATH_RESPONSE"] == 0x0B, "path response context")
    require(EQU["TRANSPORT_PATH_RESPONSE_CAPACITY"] == EQU["TRANSPORT_PATH_CAPACITY"],
            "cache mirrors path capacity")
    require(EQU["TRANSPORT_PATH_RESPONSE_RAW_MAX"] ==
            EQU["SX1262_BENCH_PAYLOAD_MAX"], "cache raw max matches LoRa max")
    require(EQU["TRANSPORT_PATH_RESPONSE_OFF_RAW"] +
            EQU["TRANSPORT_PATH_RESPONSE_RAW_MAX"] <=
            EQU["TRANSPORT_PATH_RESPONSE_ENTRY_SIZE"], "raw fits entry")


def prove_model() -> None:
    dest = bytes(range(0x10, 0x20))
    local_id = bytes(range(0xA0, 0xB0))
    h1 = bytes([0x01, 3]) + dest + bytes([0, 0xAA, 0xBB])
    got_h1 = h1_response(h1, 4, local_id)
    require(got_h1[0] == EQU["ANNOUNCE_HEADER2_FLAGS"], "H1 response flags")
    require(got_h1[1] == 4, "H1 response hops")
    require(got_h1[2:18] == local_id, "H1 response transport id")
    require(got_h1[18:34] == dest, "H1 response dest")
    require(got_h1[34] == EQU["TRANSPORT_CONTEXT_PATH_RESPONSE"],
            "H1 response context")
    require(got_h1[35:] == b"\xAA\xBB", "H1 response payload preserved")

    h2 = bytes([0x51, 6]) + bytes(range(0x70, 0x80)) + dest + bytes([0, 0xCC])
    got_h2 = h2_response(h2, 7, local_id)
    require(len(got_h2) == len(h2), "H2 length preserved")
    require(got_h2[2:18] == local_id, "H2 transport id replaced")
    require(got_h2[18:34] == dest, "H2 dest preserved")
    require(got_h2[34] == EQU["TRANSPORT_CONTEXT_PATH_RESPONSE"],
            "H2 response context")
    require(got_h2[35:] == b"\xCC", "H2 payload preserved")


def body(path: str, symbol: str) -> str:
    text = read(path)
    start = text.index(f"{symbol}:")
    end = text.index(f".size   {symbol}, . - {symbol}", start)
    return text[start:end]


def require_patterns(text: str, patterns: list[str], description: str) -> None:
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{description}: missing {pattern!r}")


def prove_source_shape() -> None:
    update = body("src/transport/transport_path_response_cache_update.S",
                  "transport_path_response_cache_update")
    require_patterns(update, [
        r"\bHEADER_H2_SIZE\b",
        r"\bSX1262_BENCH_PAYLOAD_MAX - HASH_LEN\b",
        r"\bSX1262_BENCH_PAYLOAD_MAX\b",
        r"\btransport_path_response_cache\b",
        r"\bANNOUNCE_HEADER2_FLAGS\b",
        r"\bIDENTITY_OFF_HASH\b",
        r"\bTRANSPORT_CONTEXT_PATH_RESPONSE\b",
        r"\bANNOUNCE_H2_RAW_OFF_CONTEXT\b",
    ], "cache update source")
    require(update.count("call    .Ltprcu_copy_bytes") >= 4,
            "cache update copies identity/raw/destination bytes")

    send = body("src/transport/transport_path_response_send.S",
                "transport_path_response_send")
    require_patterns(send, [
        r"\bTRANSPORT_INTERFACE_LORA\b",
        r"\bcall\s+transport_path_lookup",
        r"\bTRANSPORT_PATH_OFF_NEXT_HOP\b",
        r"\btransport_path_response_cache\b",
        r"\bTRANSPORT_PATH_RESPONSE_OFF_RAW_LEN\b",
        r"\bcall\s+lora_interface_send",
        r"\bTRANSPORT_STATUS_FORWARDED\b",
    ], "path response send source")


def main() -> None:
    prove_constants()
    prove_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
