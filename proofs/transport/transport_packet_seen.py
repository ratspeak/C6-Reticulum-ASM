#!/usr/bin/env python3
"""Finite contract/source-shape proof for transport_packet_seen."""

from __future__ import annotations

import hashlib
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
    pattern = r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))(?:\s*/\*.*)?\s*$"
    for path in paths:
        for line in read(path).splitlines():
            m = re.match(pattern, line)
            if m:
                values[m.group(1)] = int(m.group(2), 0)
    return values


EQU = parse_equ("src/include/packet.S", "src/include/transport.S", "src/include/sha256.S")


def packet_hashable(raw: bytes) -> bytes:
    if raw[0] & EQU["FLAG_HEADER_TYPE"]:
        return bytes([raw[0] & 0x0F]) + raw[EQU["HASH_LEN"] + 2 :]
    return bytes([raw[0] & 0x0F]) + raw[2:]


def packet_hash(raw: bytes) -> bytes:
    return hashlib.sha256(packet_hashable(raw)).digest()[: EQU["TRANSPORT_PACKET_HASH_SIZE"]]


def prove_constants() -> None:
    require(EQU["TRANSPORT_PACKET_HASH_SIZE"] == 16, "hash size")
    require(EQU["TRANSPORT_PACKET_HASH_CAPACITY"] == 16, "hash capacity")
    require(
        EQU["TRANSPORT_PACKET_HASH_TABLE_SIZE"]
        == EQU["TRANSPORT_PACKET_HASH_SIZE"] * EQU["TRANSPORT_PACKET_HASH_CAPACITY"],
        "hash table size",
    )
    require(EQU["TRANSPORT_STATUS_DUPLICATE"] == 2, "duplicate status")
    require(EQU["SHA256_CTX_SIZE"] == 112, "sha256 ctx size")


def prove_hashable_model() -> None:
    dest = bytes(range(0x20, 0x30))
    h1 = bytes([0x00, 0x01]) + dest + b"\x00\xaa"
    h2 = bytes([0x50, 0x09]) + bytes(range(0x80, 0x90)) + dest + b"\x00\xaa"
    other = bytes([0x00, 0x01]) + dest + b"\x00\xab"
    require(packet_hash(h1) == packet_hash(h2), "HEADER_1/HEADER_2 hash equivalence")
    require(packet_hash(h1) != packet_hash(other), "payload hash separation")


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
    src = body("src/transport/transport_packet_seen.S", "transport_packet_seen")
    require(src.count("call    packet_parse_header") == 1, "packet_parse_header call count")
    require(src.count("call    sha256_init") == 1, "sha256_init call count")
    require(src.count("call    sha256_update") == 2, "sha256_update call count")
    require(src.count("call    sha256_final") == 1, "sha256_final call count")
    require_patterns(src, [
        r"\bandi\s+t0,\s*t0,\s*0x0f",
        r"\bHASH_LEN \+ 2\b",
        r"\bTRANSPORT_PACKET_HASH_SIZE\b",
        r"\bTRANSPORT_PACKET_HASH_CAPACITY\b",
        r"\btransport_packet_hashes\b",
        r"\btransport_packet_hash_count\b",
        r"\btransport_packet_hash_next\b",
        r"\bTRANSPORT_STATUS_DUPLICATE\b",
    ])
    state = read("src/state/transport.S")
    require_patterns(state, [
        r"transport_packet_hashes",
        r"transport_packet_hash_count",
        r"transport_packet_hash_next",
    ])


def main() -> None:
    prove_constants()
    prove_hashable_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
