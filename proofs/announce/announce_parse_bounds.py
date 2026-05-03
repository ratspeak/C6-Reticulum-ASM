#!/usr/bin/env python3
"""Finite bounds verifier for milestone-5 announce_parse."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
U32_MAX = (1 << 32) - 1


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


ANN = parse_equ("src/include/config.S", "src/include/announce.S")


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


def parse_accepts(length: int, flags: int, context: int) -> bool:
    if length < ANN["ANNOUNCE_BASE_RAW_LEN"]:
        return False
    if length > ANN["ANNOUNCE_RETICULUM_MDU"]:
        return False
    if flags != ANN["ANNOUNCE_HEADER_FLAGS"]:
        return False
    if context != ANN["ANNOUNCE_CONTEXT_NONE"]:
        return False
    return True


def prove_constants() -> None:
    require(ANN["ANNOUNCE_HEADER_LEN"] == 19, "HEADER_1 announce header length")
    require(ANN["ANNOUNCE_BASE_RAW_LEN"] == 167, "fixed announce prefix")
    require(ANN["ANNOUNCE_RETICULUM_MDU"] == 484, "Reticulum MDU")
    require(ANN["ANNOUNCE_RX_OFF_RAW_LEN"] == 0, "raw_len offset")
    require(ANN["ANNOUNCE_RX_OFF_PAYLOAD_LEN"] == 4, "payload_len offset")
    require(ANN["ANNOUNCE_RX_OFF_APP_DATA_LEN"] == 8, "app_data_len offset")
    require(ANN["ANNOUNCE_RX_OFF_DEST_HASH"] == 12, "destination hash offset")
    require(ANN["ANNOUNCE_RX_OFF_PUBLIC_KEY"] == 28, "public key offset")
    require(ANN["ANNOUNCE_RX_OFF_NAME_HASH"] == 92, "name hash offset")
    require(ANN["ANNOUNCE_RX_OFF_RANDOM_HASH"] == 102, "random hash offset")
    require(ANN["ANNOUNCE_RX_OFF_SIGNATURE"] == 112, "signature offset")
    require(ANN["ANNOUNCE_RX_OFF_APP_DATA_PTR"] == 176, "app data ptr offset")
    require(ANN["ANNOUNCE_RX_T_SIZE"] == 180, "announce_rx_t size")
    require(ANN["ANNOUNCE_ERR_INVAL"] < 0, "negative error code")


def prove_acceptance_domain() -> None:
    for length in range(0, ANN["ANNOUNCE_RETICULUM_MDU"] + 2):
        accepts_good_shape = parse_accepts(
            length,
            ANN["ANNOUNCE_HEADER_FLAGS"],
            ANN["ANNOUNCE_CONTEXT_NONE"],
        )
        require(
            accepts_good_shape == (
                ANN["ANNOUNCE_BASE_RAW_LEN"]
                <= length
                <= ANN["ANNOUNCE_RETICULUM_MDU"]
            ),
            f"length predicate mismatch at {length}",
        )
        require(not parse_accepts(length, 0x00, 0x00), f"bad flags accepted at {length}")
        require(not parse_accepts(length, 0x01, 0x01), f"bad context accepted at {length}")
    require(not parse_accepts(U32_MAX, 0x01, 0x00), "u32 max length accepted")


def prove_field_ranges() -> None:
    ranges = (
        ("destination_hash", ANN["ANNOUNCE_RAW_OFF_DEST_HASH"], ANN["ANNOUNCE_DESTINATION_HASH_SIZE"]),
        ("public_key", ANN["ANNOUNCE_RAW_OFF_PUBLIC_KEY"], ANN["ANNOUNCE_PUBLIC_KEY_SIZE"]),
        ("name_hash", ANN["ANNOUNCE_RAW_OFF_NAME_HASH"], ANN["ANNOUNCE_NAME_HASH_SIZE"]),
        ("random_hash", ANN["ANNOUNCE_RAW_OFF_RANDOM_HASH"], ANN["ANNOUNCE_RANDOM_HASH_SIZE"]),
        ("signature", ANN["ANNOUNCE_RAW_OFF_SIGNATURE"], ANN["ANNOUNCE_SIGNATURE_SIZE"]),
    )
    for length in range(ANN["ANNOUNCE_BASE_RAW_LEN"], ANN["ANNOUNCE_RETICULUM_MDU"] + 1):
        for name, off, size in ranges:
            require(off + size <= length, f"{name} copy overruns accepted length {length}")
        payload_len = length - ANN["ANNOUNCE_HEADER_LEN"]
        app_len = length - ANN["ANNOUNCE_BASE_RAW_LEN"]
        require(payload_len >= 0, "negative payload len")
        require(0 <= app_len <= ANN["ANNOUNCE_MAX_APP_DATA"], "app length out of range")
        require(ANN["ANNOUNCE_RAW_OFF_APP_DATA"] + app_len == length, "app view not bounded")


def prove_source_shape() -> None:
    src = body("src/announce/announce_parse.S", "announce_parse")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Lap_fail",
            r"\bbeqz\s+s2,\s*\.Lap_fail",
            r"\bli\s+t0,\s*ANNOUNCE_BASE_RAW_LEN",
            r"\bbltu\s+s1,\s*t0,\s*\.Lap_fail",
            r"\bli\s+t0,\s*ANNOUNCE_RETICULUM_MDU",
            r"\bbltu\s+t0,\s*s1,\s*\.Lap_fail",
            r"\bcall\s+packet_parse_header",
            r"\blbu\s+t0,\s*AP_PKT_OFF \+ PKT_OFF_HEADER_TYPE\(sp\)",
            r"\bbnez\s+t0,\s*\.Lap_fail",
            r"\blbu\s+t0,\s*AP_PKT_OFF \+ PKT_OFF_PACKET_TYPE\(sp\)",
            r"\bbne\s+t0,\s*t1,\s*\.Lap_fail",
            r"\blbu\s+t0,\s*ANNOUNCE_RAW_OFF_FLAGS\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Lap_fail",
            r"\blbu\s+t0,\s*ANNOUNCE_RAW_OFF_CONTEXT\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Lap_fail",
            r"\bsw\s+s1,\s*ANNOUNCE_RX_OFF_RAW_LEN\(s2\)",
        ],
        "announce_parse validates before writing output",
    )

    before_output = src[: src.index("sw      s1, ANNOUNCE_RX_OFF_RAW_LEN(s2)")]
    require(
        not re.search(r"\b(?:sb|sh|sw)\s+\w+,\s*[^\n]*\(s2\)", before_output),
        "announce_parse writes output before validation completes",
    )
    require(src.count("call    .Lap_copy_bytes") == 5, "fixed-field copy count")
    require(
        re.search(r"\baddi\s+t0,\s*s0,\s*ANNOUNCE_RAW_OFF_APP_DATA", src),
        "app data pointer not derived from raw packet",
    )
    require(
        re.search(r"\bsw\s+t0,\s*ANNOUNCE_RX_OFF_APP_DATA_PTR\(s2\)", src),
        "app data pointer not stored",
    )


def main() -> None:
    prove_constants()
    prove_acceptance_domain()
    prove_field_ranges()
    prove_source_shape()


if __name__ == "__main__":
    main()
