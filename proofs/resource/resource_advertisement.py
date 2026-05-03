#!/usr/bin/env python3
"""Source/contract verifier for milestone-7 resource advertisements."""

from __future__ import annotations

import dataclasses
import math
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


EQU = parse_equ(
    "src/include/config.S",
    "src/include/x25519.S",
    "src/include/ed25519.S",
    "src/include/link.S",
    "src/include/resource.S",
)


@dataclasses.dataclass(frozen=True)
class Advertisement:
    transfer_size: int
    data_size: int
    part_count: int
    resource_hash: bytes
    random_hash: bytes
    original_hash: bytes
    segment_index: int
    total_segments: int
    flags: int
    hashmap: bytes


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


def mp_key(ch: str) -> bytes:
    return b"\xa1" + ch.encode("ascii")


def mp_uint(value: int) -> bytes:
    if 0 <= value <= 0x7F:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + bytes([value])
    if value <= 0xFFFF:
        return b"\xcd" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_bin(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"\xc4" + bytes([len(data)]) + data
    return b"\xc5" + len(data).to_bytes(2, "big") + data


def pack_adv(adv: Advertisement, request_nil: bool = True) -> bytes:
    q = b"\xc0" if request_nil else mp_uint(0)
    return b"\x8b" + b"".join(
        (
            mp_key("t") + mp_uint(adv.transfer_size),
            mp_key("d") + mp_uint(adv.data_size),
            mp_key("n") + mp_uint(adv.part_count),
            mp_key("h") + mp_bin(adv.resource_hash),
            mp_key("r") + mp_bin(adv.random_hash),
            mp_key("o") + mp_bin(adv.original_hash),
            mp_key("i") + mp_uint(adv.segment_index),
            mp_key("l") + mp_uint(adv.total_segments),
            mp_key("q") + q,
            mp_key("f") + mp_uint(adv.flags),
            mp_key("m") + mp_bin(adv.hashmap),
        )
    )


def parse_strict(raw: bytes) -> Advertisement:
    pos = 0

    def byte() -> int:
        nonlocal pos
        if pos >= len(raw):
            raise ValueError("short")
        out = raw[pos]
        pos += 1
        return out

    def key(expected: str) -> None:
        if byte() != 0xA1 or byte() != ord(expected):
            raise ValueError("key")

    def uint() -> int:
        marker = byte()
        if marker < 0x80:
            return marker
        if marker == 0xCC:
            return byte()
        if marker == 0xCD:
            return (byte() << 8) | byte()
        if marker == 0xCE:
            return (byte() << 24) | (byte() << 16) | (byte() << 8) | byte()
        raise ValueError("uint")

    def binval_advance() -> bytes:
        nonlocal pos
        marker = byte()
        if marker == 0xC4:
            length = byte()
        elif marker == 0xC5:
            length = (byte() << 8) | byte()
        else:
            raise ValueError("bin")
        if length > len(raw) - pos:
            raise ValueError("bin length")
        out = raw[pos:pos + length]
        pos += length
        return out

    if len(raw) > EQU["RESOURCE_ADV_MAX_RAW_LEN"]:
        raise ValueError("raw over max")
    if byte() != (0x80 | EQU["RESOURCE_ADV_MSGPACK_FIELDS"]):
        raise ValueError("field count")

    key("t")
    transfer_size = uint()
    key("d")
    data_size = uint()
    key("n")
    part_count = uint()
    key("h")
    resource_hash = binval_advance()
    key("r")
    random_hash = binval_advance()
    key("o")
    original_hash = binval_advance()
    key("i")
    segment_index = uint()
    key("l")
    total_segments = uint()
    key("q")
    if byte() != 0xC0:
        raise ValueError("request id")
    key("f")
    flags = uint()
    key("m")
    hashmap = binval_advance()
    if pos != len(raw):
        raise ValueError("extra")

    adv = Advertisement(
        transfer_size,
        data_size,
        part_count,
        resource_hash,
        random_hash,
        original_hash,
        segment_index,
        total_segments,
        flags,
        hashmap,
    )
    validate(adv)
    return adv


def validate(adv: Advertisement) -> None:
    if adv.transfer_size == 0 or adv.data_size == 0 or adv.part_count == 0:
        raise ValueError("zero")
    if adv.part_count > EQU["RESOURCE_ADV_MAX_PARTS"]:
        raise ValueError("too many parts")
    if adv.flags != EQU["RESOURCE_ADV_FLAGS_ENCRYPTED"]:
        raise ValueError("flags")
    if adv.segment_index != 1 or adv.total_segments != 1:
        raise ValueError("segments")
    if len(adv.resource_hash) != EQU["RESOURCE_HASH_SIZE"]:
        raise ValueError("hash")
    if len(adv.random_hash) != EQU["RESOURCE_RANDOM_HASH_SIZE"]:
        raise ValueError("random")
    if adv.original_hash != adv.resource_hash:
        raise ValueError("original")
    if len(adv.hashmap) != adv.part_count * EQU["RESOURCE_MAPHASH_SIZE"]:
        raise ValueError("hashmap")
    if len(adv.hashmap) > EQU["RESOURCE_ADV_MAX_HASHMAP_BYTES"]:
        raise ValueError("hashmap max")
    expected_parts = math.ceil(adv.transfer_size / EQU["RESOURCE_PART_MAX_LEN"])
    if expected_parts != adv.part_count:
        raise ValueError("part count")
    if adv.data_size > adv.transfer_size:
        raise ValueError("data size")


def prove_constants() -> None:
    require(EQU["RESOURCE_ADV_MSGPACK_FIELDS"] == 11, "field count")
    require(EQU["RESOURCE_ADV_FLAGS_ENCRYPTED"] == 1, "encrypted flag")
    require(EQU["RESOURCE_ADV_MAX_PARTS"] == 64, "max parts")
    require(EQU["RESOURCE_ADV_MAX_HASHMAP_BYTES"] == 256, "max hashmap bytes")
    require(EQU["RESOURCE_ADV_MAX_RAW_LEN"] == 431, "max raw len")
    require(EQU["RESOURCE_ADV_T_SIZE"] == 104, "struct size")
    require(EQU["RESOURCE_ADV_OFF_RESOURCE_HASH"] + 32 ==
            EQU["RESOURCE_ADV_OFF_RANDOM_HASH"], "resource hash end")
    require(EQU["RESOURCE_ADV_OFF_RANDOM_HASH"] + 4 ==
            EQU["RESOURCE_ADV_OFF_ORIGINAL_HASH"], "random hash end")
    require(EQU["RESOURCE_ADV_OFF_ORIGINAL_HASH"] + 32 ==
            EQU["RESOURCE_ADV_OFF_HASHMAP_LEN"], "original hash end")


def prove_vectors() -> None:
    adv = Advertisement(
        transfer_size=128,
        data_size=96,
        part_count=1,
        resource_hash=bytes(range(32)),
        random_hash=b"RND0",
        original_hash=bytes(range(32)),
        segment_index=1,
        total_segments=1,
        flags=1,
        hashmap=b"MAP0",
    )
    raw = pack_adv(adv)
    require(parse_strict(raw) == adv, "valid advertisement rejected")

    max_adv = Advertisement(
        transfer_size=EQU["RESOURCE_ADV_MAX_PARTS"] * EQU["RESOURCE_PART_MAX_LEN"],
        data_size=EQU["RESOURCE_ADV_MAX_PARTS"] * EQU["RESOURCE_PART_MAX_LEN"] - 1,
        part_count=EQU["RESOURCE_ADV_MAX_PARTS"],
        resource_hash=bytes([0x11]) * 32,
        random_hash=bytes([0x22]) * 4,
        original_hash=bytes([0x11]) * 32,
        segment_index=1,
        total_segments=1,
        flags=1,
        hashmap=bytes(range(256)),
    )
    require(parse_strict(pack_adv(max_adv)) == max_adv, "max advertisement rejected")

    bad_cases = [
        dataclasses.replace(adv, flags=3),
        dataclasses.replace(adv, part_count=2),
        dataclasses.replace(adv, segment_index=2),
        dataclasses.replace(adv, data_size=129),
        dataclasses.replace(adv, original_hash=bytes([9]) * 32),
    ]
    for bad in bad_cases:
        try:
            parse_strict(pack_adv(bad))
        except ValueError:
            pass
        else:
            raise ProofError(f"bad advertisement accepted: {bad!r}")


def prove_source_shape() -> None:
    src = body(
        "src/resource/resource_advertisement_parse.S",
        "resource_advertisement_parse",
    )
    ordered(
        src,
        [
            r"\bli\s+t0,\s*RESOURCE_ADV_MAX_RAW_LEN",
            r"\bli\s+t0,\s*0x80\s*\|\s*RESOURCE_ADV_MSGPACK_FIELDS",
            r"\bli\s+a0,\s*0x74",
            r"\bli\s+a0,\s*0x64",
            r"\bli\s+a0,\s*0x6e",
            r"\bli\s+a0,\s*0x68",
            r"\bli\s+a0,\s*0x72",
            r"\bli\s+a0,\s*0x6f",
            r"\bli\s+a0,\s*0x69",
            r"\bli\s+a0,\s*0x6c",
            r"\bli\s+a0,\s*0x71",
            r"\bcall\s+\.Lrap_expect_nil",
            r"\bli\s+a0,\s*0x66",
            r"\bli\s+a0,\s*0x6d",
            r"\bbne\s+s3,\s*s4,\s*\.Lrap_invalid",
            r"\bli\s+t0,\s*RESOURCE_ADV_MAX_PARTS",
            r"\bli\s+t0,\s*RESOURCE_ADV_FLAGS_ENCRYPTED",
            r"\bslli\s+t0,\s*s7,\s*2",
            r"\bmul\s+t2,\s*s7,\s*t1",
            r"\bcall\s+\.Lrap_memeq",
            r"\bsw\s+s1,\s*RESOURCE_ADV_OFF_RAW_LEN\(s2\)",
        ],
        "advertisement parser pins key order and strict subset checks",
    )
    require(src.count("call    .Lrap_parse_bin") == 4, "four bin fields")
    require(src.count("call    .Lrap_parse_uint") == 6, "six uint fields")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
