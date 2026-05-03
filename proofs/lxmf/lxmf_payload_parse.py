#!/usr/bin/env python3
"""Source/contract verifier for LXMF payload parsing."""

from __future__ import annotations

import dataclasses
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


@dataclasses.dataclass(frozen=True)
class Parsed:
    timestamp_be: bytes
    title: bytes
    content: bytes
    fields_bytes: bytes
    stamp: bytes
    without_stamp: bytes


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


def mp_bin8(data: bytes) -> bytes:
    require(len(data) <= 0xFF, "bin8 cap")
    return b"\xc4" + bytes([len(data)]) + data


def skip_scalar(raw: bytes, pos: int) -> int:
    if pos >= len(raw):
        raise ValueError("short scalar")
    marker = raw[pos]
    pos += 1
    if marker < 0x80 or marker in (0xC0, 0xC2, 0xC3):
        return pos
    if 0xA0 <= marker <= 0xBF:
        n = marker & 0x1F
    elif marker in (0xC4, 0xD9):
        if pos >= len(raw):
            raise ValueError("short scalar len")
        n = raw[pos]
        pos += 1
    elif marker == 0xCC:
        n = 1
    elif marker == 0xCD:
        n = 2
    elif marker == 0xCE:
        n = 4
    else:
        raise ValueError("unsupported scalar")
    if len(raw) - pos < n:
        raise ValueError("short scalar data")
    return pos + n


def skip_fields(raw: bytes, pos: int) -> int:
    start = pos
    if pos >= len(raw):
        raise ValueError("short map")
    marker = raw[pos]
    pos += 1
    if 0x80 <= marker <= 0x8F:
        count = marker & 0x0F
    elif marker == 0xDE:
        if len(raw) - pos < 2:
            raise ValueError("short map16")
        count = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2
    elif marker == 0xDF:
        if len(raw) - pos < 4:
            raise ValueError("short map32")
        count = int.from_bytes(raw[pos:pos + 4], "big")
        pos += 4
    else:
        raise ValueError("not map")
    if pos - start > EQU["LXMF_PAYLOAD_MAX_FIELDS"]:
        raise OverflowError("fields")
    for _ in range(count):
        pos = skip_scalar(raw, pos)
        if pos - start > EQU["LXMF_PAYLOAD_MAX_FIELDS"]:
            raise OverflowError("fields")
        pos = skip_scalar(raw, pos)
        if pos - start > EQU["LXMF_PAYLOAD_MAX_FIELDS"]:
            raise OverflowError("fields")
    return pos


def parse_payload(raw: bytes) -> Parsed:
    if len(raw) > EQU["LXMF_PAYLOAD_MAX_STAMPED_LEN"]:
        raise OverflowError("raw")
    pos = 0
    if not raw:
        raise ValueError("short")
    marker = raw[pos]
    pos += 1
    if marker == EQU["LXMF_MSGPACK_FIXARRAY4"]:
        has_stamp = False
    elif marker == EQU["LXMF_MSGPACK_FIXARRAY5"]:
        has_stamp = True
    else:
        raise ValueError("array")
    if pos >= len(raw) or raw[pos] != EQU["LXMF_MSGPACK_FLOAT64"]:
        raise ValueError("timestamp marker")
    pos += 1
    if len(raw) - pos < EQU["LXMF_TIMESTAMP_SIZE"]:
        raise ValueError("timestamp")
    timestamp = raw[pos:pos + EQU["LXMF_TIMESTAMP_SIZE"]]
    pos += EQU["LXMF_TIMESTAMP_SIZE"]
    if pos + 2 > len(raw) or raw[pos] != EQU["LXMF_MSGPACK_BIN8"]:
        raise ValueError("title")
    title_len = raw[pos + 1]
    pos += 2
    if title_len > EQU["LXMF_PAYLOAD_MAX_TITLE"]:
        raise OverflowError("title")
    title = raw[pos:pos + title_len]
    if len(title) != title_len:
        raise ValueError("title short")
    pos += title_len
    if pos + 2 > len(raw) or raw[pos] != EQU["LXMF_MSGPACK_BIN8"]:
        raise ValueError("content")
    content_len = raw[pos + 1]
    pos += 2
    if content_len > EQU["LXMF_PAYLOAD_MAX_CONTENT"]:
        raise OverflowError("content")
    content = raw[pos:pos + content_len]
    if len(content) != content_len:
        raise ValueError("content short")
    pos += content_len
    fields_start = pos
    pos = skip_fields(raw, pos)
    fields = raw[fields_start:pos]
    if len(fields) > EQU["LXMF_PAYLOAD_MAX_FIELDS"]:
        raise OverflowError("fields")
    without_len = pos
    if without_len > EQU["LXMF_PAYLOAD_MAX_LEN"]:
        raise OverflowError("payload")
    if has_stamp:
        if pos + 2 > len(raw) or raw[pos] != EQU["LXMF_MSGPACK_BIN8"]:
            raise ValueError("stamp")
        stamp_len = raw[pos + 1]
        pos += 2
        if stamp_len == 0:
            raise ValueError("stamp empty")
        if stamp_len > EQU["LXMF_STAMP_MAX_LEN"]:
            raise OverflowError("stamp")
        stamp = raw[pos:pos + stamp_len]
        if len(stamp) != stamp_len:
            raise ValueError("stamp short")
        pos += stamp_len
        without = bytes([EQU["LXMF_MSGPACK_FIXARRAY4"]]) + raw[1:without_len]
    else:
        stamp = b""
        without = raw
    if pos != len(raw):
        raise ValueError("extra")
    return Parsed(timestamp, title, content, fields, stamp, without)


def prove_constants() -> None:
    require(EQU["LXMF_MSGPACK_FIXARRAY5"] == 0x95, "array5 marker")
    require(EQU["LXMF_STAMP_MAX_LEN"] == 32, "stamp cap")
    require(EQU["LXMF_PAYLOAD_MAX_STAMPED_LEN"] == 431, "stamped cap")
    require(EQU["LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_BUF"] == 56, "buffer offset")
    require(EQU["LXMF_PAYLOAD_PARSED_T_SIZE"] == 456, "parsed struct size")


def prove_vectors() -> None:
    vectors = [
        [1.5, b"Title", b"Body", {}],
        [1700000000.0, b"", b"", {0xFB: b"abc"}],
        [1.5, bytes(range(64)), bytes(range(255)), {0xFB: b"A" * 58}],
        [1.5, b"T", b"C", {}, b"\x11" * 16],
        [1.5, b"T", b"C", {}, b"\x22" * 32],
        [1.5, b"T", b"C", {i: i for i in range(16)}],
    ]
    for payload in vectors:
        raw = msgpack.packb(payload)
        parsed = parse_payload(raw)
        unpacked = msgpack.unpackb(raw)
        if len(unpacked) > 4:
            without = msgpack.packb(unpacked[:4])
            stamp = unpacked[4]
        else:
            without = raw
            stamp = b""
        require(parsed.without_stamp == without, "without-stamp bytes")
        require(parsed.timestamp_be == struct.pack(">d", unpacked[0]), "timestamp bytes")
        require(parsed.title == unpacked[1], "title bytes")
        require(parsed.content == unpacked[2], "content bytes")
        require(parsed.fields_bytes == msgpack.packb(unpacked[3]), "field bytes")
        require(parsed.stamp == stamp, "stamp bytes")
    for bad in [
        b"",
        b"\x93",
        msgpack.packb([1.5, b"A" * 65, b"", {}]),
        msgpack.packb([1.5, b"", b"", {0xFB: b"A" * 60}]),
        msgpack.packb([1.5, b"", b"", {1: [2]}]),
        b"\x95\xcb" + struct.pack(">d", 1.5) + mp_bin8(b"T") + mp_bin8(b"C") + b"\x80\xc0",
    ]:
        try:
            parse_payload(bad)
        except (ValueError, OverflowError):
            pass
        else:
            raise ProofError(f"bad payload accepted: {bad.hex()}")


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_payload_parse.S", "lxmf_payload_parse")
    ordered(
        src,
        [
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_STAMPED_LEN",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FIXARRAY4",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FIXARRAY5",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FLOAT64",
            r"\bcall\s+\.Llpp_parse_bin8",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_TITLE",
            r"\bcall\s+\.Llpp_parse_bin8",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_CONTENT",
            r"\bcall\s+\.Llpp_parse_fields_map",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_FIELDS",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_LEN",
            r"\bcall\s+\.Llpp_parse_bin8",
            r"\bli\s+t0,\s*LXMF_STAMP_MAX_LEN",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FIXARRAY4",
            r"\bcall\s+\.Llpp_copy_bytes",
        ],
        "payload parse/normalise order",
    )
    require("0xDE" in src and "0xDF" in src, "map16/map32 accepted")
    require("0xA0" in src and "0xBF" in src and "0xD9" in src, "field scalar str support")
    require("LXMF_ERR_OVERFLOW" in src, "overflow return exists")
    require(src.count("call    .Llpp_check_fields_cap") >= 3, "field cap checks")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
