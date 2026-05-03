#!/usr/bin/env python3
"""Source/contract verifier for LXMF payload construction."""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))

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


EQU = parse_equ("src/include/config.S", "src/include/lxmf.S")


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


def payload(timestamp: float, title: bytes, content: bytes, fields: bytes = b"\x80") -> bytes:
    require(len(title) <= EQU["LXMF_PAYLOAD_MAX_TITLE"], "title cap")
    require(len(content) <= EQU["LXMF_PAYLOAD_MAX_CONTENT"], "content cap")
    require(len(fields) <= EQU["LXMF_PAYLOAD_MAX_FIELDS"], "fields cap")
    ts = struct.pack(">d", timestamp)
    out = bytearray([EQU["LXMF_MSGPACK_FIXARRAY4"], EQU["LXMF_MSGPACK_FLOAT64"]])
    out.extend(ts)
    out.extend((EQU["LXMF_MSGPACK_BIN8"], len(title)))
    out.extend(title)
    out.extend((EQU["LXMF_MSGPACK_BIN8"], len(content)))
    out.extend(content)
    out.extend(fields)
    return bytes(out)


def prove_constants() -> None:
    require(EQU["LXMF_MSGPACK_FIXARRAY4"] == 0x94, "array4 marker")
    require(EQU["LXMF_MSGPACK_FLOAT64"] == 0xCB, "float64 marker")
    require(EQU["LXMF_PAYLOAD_MAX_TITLE"] == 64, "title cap")
    require(EQU["LXMF_PAYLOAD_MAX_CONTENT"] == 255, "content cap")
    require(EQU["LXMF_PAYLOAD_MAX_FIELDS"] == 64, "fields cap")
    require(EQU["LXMF_PAYLOAD_MAX_LEN"] == 397, "payload cap")


def prove_vectors() -> None:
    cases = [
        (0.0, b"Title", b"Body", b"\x80"),
        (1700000000.0, b"Title", b"Body", b"\x80"),
        (1.5, b"", b"", b"\x80"),
        (1.5, b"Title", b"Body", msgpack.packb({0xFB: b"abc"})),
        (1.5, bytes(range(64)), bytes(range(255)), b"\x80"),
    ]
    for ts, title, content, fields in cases:
        local = payload(ts, title, content, fields)
        # Verify against upstream MessagePack for the same four LXMF fields.
        upstream = msgpack.packb([ts, title, content, msgpack.unpackb(fields)])
        require(local == upstream, f"payload mismatch for {ts}, {title!r}, {content!r}")
    require(
        payload(1700000000.0, b"Title", b"Body").hex()
        == "94cb41d954fc40000000c4055469746c65c404426f647980",
        "known upstream vector",
    )


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_payload_build.S", "lxmf_payload_build")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llpb_invalid",
            r"\bbeqz\s+s1,\s*\.Llpb_invalid",
            r"\blw\s+s3,\s*LXMF_PAYLOAD_IN_OFF_TIMESTAMP_BE_PTR\(s0\)",
            r"\bbeqz\s+s3,\s*\.Llpb_invalid",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_TITLE",
            r"\bbltu\s+t0,\s*s5,\s*\.Llpb_overflow",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_CONTENT",
            r"\bbltu\s+t0,\s*s7,\s*\.Llpb_overflow",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_FIELDS",
            r"\bbltu\s+t0,\s*t6,\s*\.Llpb_overflow",
            r"\bli\s+t1,\s*0xDE",
            r"\bli\s+t1,\s*3",
            r"\bbltu\s+t6,\s*t1,\s*\.Llpb_invalid",
            r"\bli\s+t1,\s*5",
            r"\bbltu\s+t6,\s*t1,\s*\.Llpb_invalid",
            r"\bli\s+s8,\s*14",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FIXARRAY4",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FLOAT64",
            r"\bli\s+a2,\s*8",
            r"\bcall\s+\.Llpb_copy_bytes",
            r"\bli\s+t0,\s*LXMF_MSGPACK_BIN8",
            r"\bcall\s+\.Llpb_copy_bytes",
            r"\bli\s+t0,\s*LXMF_MSGPACK_BIN8",
            r"\bcall\s+\.Llpb_copy_bytes",
            r"\bcall\s+\.Llpb_copy_bytes",
        ],
        "payload validation/encoding order",
    )


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
