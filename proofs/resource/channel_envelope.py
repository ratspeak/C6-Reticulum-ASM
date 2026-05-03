#!/usr/bin/env python3
"""Source/contract verifier for milestone-7 channel envelopes."""

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


def envelope(msgtype: int, sequence: int, payload: bytes) -> bytes:
    require(0 <= msgtype <= 0xFFFF, "msgtype range")
    require(0 <= sequence <= 0xFFFF, "sequence range")
    require(len(payload) <= EQU["CHANNEL_ENVELOPE_MAX_PAYLOAD"], "payload range")
    return (
        msgtype.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + len(payload).to_bytes(2, "big")
        + payload
    )


def parse(raw: bytes) -> tuple[int, int, bytes]:
    if len(raw) < EQU["CHANNEL_ENVELOPE_HEADER_LEN"]:
        raise ValueError("short envelope")
    if len(raw) > EQU["CHANNEL_ENVELOPE_MAX_RAW_LEN"]:
        raise ValueError("over max")
    msgtype = int.from_bytes(raw[0:2], "big")
    sequence = int.from_bytes(raw[2:4], "big")
    payload_len = int.from_bytes(raw[4:6], "big")
    if payload_len > EQU["CHANNEL_ENVELOPE_MAX_PAYLOAD"]:
        raise ValueError("payload over max")
    if len(raw) != EQU["CHANNEL_ENVELOPE_HEADER_LEN"] + payload_len:
        raise ValueError("length mismatch")
    return msgtype, sequence, raw[6:]


def prove_constants() -> None:
    require(EQU["CHANNEL_ENVELOPE_HEADER_LEN"] == 6, "envelope header")
    require(EQU["CHANNEL_ENVELOPE_MAX_PAYLOAD"] == 425, "envelope payload max")
    require(EQU["CHANNEL_ENVELOPE_MAX_RAW_LEN"] == 431, "envelope raw max")
    require(EQU["CHANNEL_ENV_T_SIZE"] == 20, "parsed struct size")


def prove_vectors() -> None:
    payload = b"hello"
    raw = envelope(0x1234, 0x0102, payload)
    require(raw.hex() == "12340102000568656c6c6f", "build vector")
    require(parse(raw) == (0x1234, 0x0102, payload), "parse vector")
    for bad in (raw[:-1], b"\x00\x01", envelope(1, 2, b"A" * 425) + b"\x00"):
        try:
            parse(bad)
        except ValueError:
            pass
        else:
            raise ProofError(f"bad envelope accepted: {bad.hex()}")


def prove_build_source_shape() -> None:
    src = body("src/resource/channel_envelope_build.S", "channel_envelope_build")
    ordered(
        src,
        [
            r"\bbeqz\s+s4,\s*\.Lceb_invalid",
            r"\bli\s+t0,\s*0xFFFF",
            r"\bbltu\s+t0,\s*s0,\s*\.Lceb_invalid",
            r"\bbltu\s+t0,\s*s1,\s*\.Lceb_invalid",
            r"\bli\s+t0,\s*CHANNEL_ENVELOPE_MAX_PAYLOAD",
            r"\bbltu\s+t0,\s*s3,\s*\.Lceb_overflow",
            r"\bbltu\s+s5,\s*s6,\s*\.Lceb_overflow",
            r"\bsb\s+t0,\s*0\(s4\)",
            r"\bsb\s+s0,\s*1\(s4\)",
            r"\bsb\s+t0,\s*2\(s4\)",
            r"\bsb\s+s1,\s*3\(s4\)",
            r"\bsb\s+t0,\s*4\(s4\)",
            r"\bsb\s+s3,\s*5\(s4\)",
            r"\bcall\s+\.Lceb_copy_bytes",
        ],
        "build validation/header/copy order",
    )


def prove_parse_source_shape() -> None:
    src = body("src/resource/channel_envelope_parse.S", "channel_envelope_parse")
    ordered(
        src,
        [
            r"\bbeqz\s+a0,\s*\.Lcep_invalid",
            r"\bbeqz\s+a2,\s*\.Lcep_invalid",
            r"\bli\s+t0,\s*CHANNEL_ENVELOPE_HEADER_LEN",
            r"\bbltu\s+a1,\s*t0,\s*\.Lcep_invalid",
            r"\bli\s+t0,\s*CHANNEL_ENVELOPE_MAX_RAW_LEN",
            r"\bbltu\s+t0,\s*a1,\s*\.Lcep_invalid",
            r"\blbu\s+t0,\s*0\(a0\)",
            r"\blbu\s+t2,\s*2\(a0\)",
            r"\blbu\s+t4,\s*4\(a0\)",
            r"\bli\s+t5,\s*CHANNEL_ENVELOPE_MAX_PAYLOAD",
            r"\bbltu\s+t5,\s*t4,\s*\.Lcep_invalid",
            r"\bbne\s+t6,\s*a1,\s*\.Lcep_invalid",
            r"\bsw\s+a1,\s*CHANNEL_ENV_OFF_RAW_LEN\(a2\)",
            r"\bsw\s+t5,\s*CHANNEL_ENV_OFF_PAYLOAD_PTR\(a2\)",
        ],
        "parse validation/decode/store order",
    )


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_build_source_shape()
    prove_parse_source_shape()


if __name__ == "__main__":
    main()
