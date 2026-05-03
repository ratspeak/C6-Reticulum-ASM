#!/usr/bin/env python3
"""Source/contract verifier for milestone-7 resource part parsing."""

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
    "src/include/sha256.S",
    "src/include/resource.S",
)


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


def part_parse(payload: bytes, random_hash: bytes) -> bytes:
    if len(payload) > EQU["RESOURCE_PART_MAX_LEN"]:
        raise ValueError("payload overflow")
    require(len(random_hash) == EQU["RESOURCE_RANDOM_HASH_SIZE"], "random hash size")
    return hashlib.sha256(payload + random_hash).digest()[:EQU["RESOURCE_MAPHASH_SIZE"]]


def prove_constants() -> None:
    require(EQU["RESOURCE_PART_MAX_LEN"] == 431, "part max len")
    require(EQU["RESOURCE_PART_OFF_PAYLOAD_LEN"] == 0, "payload len offset")
    require(EQU["RESOURCE_PART_OFF_PAYLOAD_PTR"] == 4, "payload ptr offset")
    require(EQU["RESOURCE_PART_OFF_MAPHASH"] == 8, "maphash offset")
    require(EQU["RESOURCE_PART_T_SIZE"] == 12, "part struct size")
    require(
        EQU["RESOURCE_PART_OFF_MAPHASH"] + EQU["RESOURCE_MAPHASH_SIZE"]
        == EQU["RESOURCE_PART_T_SIZE"],
        "maphash ends at struct size",
    )
    require(EQU["RESOURCE_RANDOM_HASH_SIZE"] == 4, "random hash size")
    require(EQU["RESOURCE_MAPHASH_SIZE"] == 4, "maphash size")


def prove_vectors() -> None:
    require(
        part_parse(b"resource-part", b"\x01\x02\x03\x04").hex() == "c51cc090",
        "short vector",
    )
    require(
        part_parse(b"", b"\x10\x20\x30\x40").hex() == "f4e3f0b0",
        "empty vector",
    )
    try:
        part_parse(bytes(EQU["RESOURCE_PART_MAX_LEN"] + 1), b"\x00\x00\x00\x00")
    except ValueError:
        pass
    else:
        raise ProofError("overflow accepted")


def prove_source_shape() -> None:
    src = body("src/resource/resource_part_parse.S", "resource_part_parse")
    ordered(
        src,
        [
            r"\bbeqz\s+s2,\s*\.Lrpp_invalid",
            r"\bbeqz\s+s3,\s*\.Lrpp_invalid",
            r"\bbeqz\s+s1,\s*\.Lrpp_len_ok",
            r"\bbeqz\s+s0,\s*\.Lrpp_invalid",
            r"\bli\s+t0,\s*RESOURCE_PART_MAX_LEN",
            r"\bbltu\s+t0,\s*s1,\s*\.Lrpp_overflow",
            r"\bsw\s+s1,\s*RESOURCE_PART_OFF_PAYLOAD_LEN\(s3\)",
            r"\bsw\s+s0,\s*RESOURCE_PART_OFF_PAYLOAD_PTR\(s3\)",
            r"\bcall\s+sha256_init",
            r"\bbeqz\s+s1,\s*\.Lrpp_random_hash",
            r"\bcall\s+sha256_update",
            r"\bli\s+a2,\s*RESOURCE_RANDOM_HASH_SIZE",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_final",
            r"\bli\s+t2,\s*RESOURCE_MAPHASH_SIZE",
            r"\.Lrpp_copy_maphash:",
            r"\bsb\s+t3,\s*0\(t1\)",
            r"\bli\s+a0,\s*RESOURCE_OK",
        ],
        "resource_part_parse validates, hashes payload/random_hash, and stores view",
    )
    require(src.count("call    sha256_update") == 2, "payload and random_hash updates")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
