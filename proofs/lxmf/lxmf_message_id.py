#!/usr/bin/env python3
"""Source/contract verifier for LXMF message-id hashing."""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))

import RNS  # noqa: E402
import RNS.vendor.umsgpack as msgpack  # noqa: E402


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


EQU = parse_equ("src/include/config.S", "src/include/sha256.S", "src/include/lxmf.S")


def body(path: str, symbol: str) -> str:
    text = read(path)
    start = text.index(f"{symbol}:")
    end = text.index(f".size   {symbol}, . - {symbol}", start)
    return text[start:end]


def ordered(src: str, patterns: list[str], description: str) -> None:
    pos = -1
    for pattern in patterns:
        match = re.search(pattern, src[pos + 1:], re.MULTILINE)
        require(match is not None, f"{description}: missing {pattern!r}")
        pos = pos + 1 + match.start()


def message_id(dest: bytes, source: bytes, payload_without_stamp: bytes) -> bytes:
    require(len(dest) == EQU["LXMF_HASH_SIZE"], "dest hash length")
    require(len(source) == EQU["LXMF_HASH_SIZE"], "source hash length")
    require(0 < len(payload_without_stamp) <= EQU["LXMF_PAYLOAD_MAX_LEN"], "payload length")
    material = dest + source + payload_without_stamp
    local = hashlib.sha256(material).digest()
    upstream = RNS.Identity.full_hash(material)
    require(local == upstream, "upstream full_hash is SHA-256")
    return local


def prove_constants() -> None:
    require(EQU["LXMF_HASH_SIZE"] == 16, "hash size")
    require(EQU["LXMF_MESSAGE_ID_SIZE"] == 32, "message id size")
    require(EQU["SHA256_CTX_SIZE"] == 112, "sha256 ctx size")
    require(EQU["SHA256_DIGEST_SIZE"] == 32, "sha256 digest size")


def prove_vectors() -> None:
    dest = bytes(range(16))
    source = bytes(range(16, 32))
    payloads = [
        msgpack.packb([1.5, b"Title", b"Body", {}]),
        msgpack.packb([1700000000.0, b"", b"", {0xFB: b"abc"}]),
        msgpack.packb([1.5, bytes(range(64)), bytes(range(255)), {0xFB: b"A" * 58}]),
    ]
    stamped = msgpack.packb([1.5, b"T", b"C", {}, b"\x11" * 16])
    unpacked = msgpack.unpackb(stamped)
    payloads.append(msgpack.packb(unpacked[:4]))
    for payload in payloads:
        got = message_id(dest, source, payload)
        require(got == hashlib.sha256(dest + source + payload).digest(), "digest vector")
    require(
        message_id(dest, source, msgpack.packb([1.5, b"Title", b"Body", {}])).hex()
        == "98917cbfc56ec420599f5c833742f860ed5f027b1a1567a1762c454b8caa4db4",
        "known vector",
    )
    try:
        message_id(dest, source, b"")
    except ProofError:
        pass
    else:
        raise ProofError("empty payload accepted")


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_message_id.S", "lxmf_message_id")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llmi_invalid",
            r"\bbeqz\s+s1,\s*\.Llmi_invalid",
            r"\bbeqz\s+s2,\s*\.Llmi_invalid",
            r"\bbeqz\s+s3,\s*\.Llmi_invalid",
            r"\bbeqz\s+s4,\s*\.Llmi_invalid",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_LEN",
            r"\bcall\s+sha256_init",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+sha256_update",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+sha256_update",
            r"\bmv\s+a2,\s*s3",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_final",
        ],
        "message-id validation and hash order",
    )
    require(src.count("call    sha256_update") == 3, "dest/source/payload updates")
    require("LXMF_ERR_OVERFLOW" in src and "LXMF_ERR_INVAL" in src, "stable errors")
    require("@ct:          required" in read("src/lxmf/lxmf_message_id.S"), "ct annotation")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
