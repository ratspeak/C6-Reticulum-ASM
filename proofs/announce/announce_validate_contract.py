#!/usr/bin/env python3
"""Contract verifier for milestone-5 announce_validate."""

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


def validate_shape(raw_len: int, payload_len: int, app_len: int, app_ptr: int) -> bool:
    if raw_len < ANN["ANNOUNCE_BASE_RAW_LEN"]:
        return False
    if raw_len > ANN["ANNOUNCE_RETICULUM_MDU"]:
        return False
    h1_shape = (
        app_len == raw_len - ANN["ANNOUNCE_BASE_RAW_LEN"]
        and payload_len == raw_len - ANN["ANNOUNCE_HEADER_LEN"]
    )
    h2_shape = (
        raw_len >= ANN["ANNOUNCE_H2_BASE_RAW_LEN"]
        and app_len == raw_len - ANN["ANNOUNCE_H2_BASE_RAW_LEN"]
        and payload_len == raw_len - ANN["ANNOUNCE_H2_HEADER_LEN"]
    )
    if not (h1_shape or h2_shape):
        return False
    if app_len > ANN["ANNOUNCE_MAX_APP_DATA"]:
        return False
    if app_len and app_ptr == 0:
        return False
    return True


def prove_constants() -> None:
    require(ANN["ANNOUNCE_SIGNED_FIXED_LEN"] == 100, "signed fixed prefix")
    require(ANN["ANNOUNCE_SIGNED_DATA_MAX"] == 417, "signed data capacity")
    require(
        ANN["ANNOUNCE_SIGNED_FIXED_LEN"] + ANN["ANNOUNCE_MAX_APP_DATA"]
        == ANN["ANNOUNCE_SIGNED_DATA_MAX"],
        "signed data max must cover fixed fields plus max app data",
    )
    require(ANN["ANNOUNCE_RX_OFF_SIGNATURE"] + ANN["ANNOUNCE_SIGNATURE_SIZE"] == 176,
            "signature ends before app pointer")


def prove_shape_model() -> None:
    base = ANN["ANNOUNCE_BASE_RAW_LEN"]
    h2_base = ANN["ANNOUNCE_H2_BASE_RAW_LEN"]
    mdu = ANN["ANNOUNCE_RETICULUM_MDU"]
    for raw_len in range(base, mdu + 1):
        payload_len = raw_len - ANN["ANNOUNCE_HEADER_LEN"]
        app_len = raw_len - base
        require(validate_shape(raw_len, payload_len, app_len, 1),
                f"valid shape rejected at {raw_len}")
        require(not validate_shape(raw_len, payload_len + 1, app_len, 1),
                f"bad payload len accepted at {raw_len}")
        require(not validate_shape(raw_len, payload_len, app_len + 1, 1),
                f"bad app len accepted at {raw_len}")
        if app_len:
            require(not validate_shape(raw_len, payload_len, app_len, 0),
                    f"null app ptr accepted at {raw_len}")
    for raw_len in range(h2_base, mdu + 1):
        payload_len = raw_len - ANN["ANNOUNCE_H2_HEADER_LEN"]
        app_len = raw_len - h2_base
        require(validate_shape(raw_len, payload_len, app_len, 1),
                f"valid H2 shape rejected at {raw_len}")
        require(not validate_shape(raw_len, payload_len + 1, app_len, 1),
                f"bad H2 payload len accepted at {raw_len}")
        require(not validate_shape(raw_len, payload_len, app_len + 1, 1),
                f"bad H2 app len accepted at {raw_len}")
        if app_len:
            require(not validate_shape(raw_len, payload_len, app_len, 0),
                    f"null H2 app ptr accepted at {raw_len}")
    require(not validate_shape(base - 1, 0, 0, 1), "short raw len accepted")
    require(not validate_shape(mdu + 1, 0, 0, 1), "over-MDU raw len accepted")


def prove_source_shape() -> None:
    src = body("src/announce/announce_validate.S", "announce_validate")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Lav_fail",
            r"\blw\s+t0,\s*ANNOUNCE_RX_OFF_RAW_LEN\(s0\)",
            r"\bbltu\s+t0,\s*t1,\s*\.Lav_fail",
            r"\bbltu\s+t1,\s*t0,\s*\.Lav_fail",
            r"\blw\s+s1,\s*ANNOUNCE_RX_OFF_APP_DATA_LEN\(s0\)",
            r"\bbne\s+s1,\s*t2,\s*\.Lav_try_h2_shape",
            r"\blw\s+t3,\s*ANNOUNCE_RX_OFF_PAYLOAD_LEN\(s0\)",
            r"\bbeq\s+t3,\s*t2,\s*\.Lav_shape_ok",
            r"\.Lav_try_h2_shape:",
            r"\bANNOUNCE_H2_BASE_RAW_LEN\b",
            r"\bANNOUNCE_H2_HEADER_LEN\b",
            r"\.Lav_shape_ok:",
            r"\blw\s+s3,\s*ANNOUNCE_RX_OFF_APP_DATA_PTR\(s0\)",
            r"\bbeqz\s+s1,\s*\.Lav_app_ptr_ok",
            r"\bbeqz\s+s3,\s*\.Lav_fail",
            r"\bcall\s+identity_hash",
            r"\bcall\s+destination_hash",
            r"\bcall\s+\.Lav_memeq",
            r"\bbnez\s+a0,\s*\.Lav_fail",
            r"\bla\s+s2,\s*announce_signed_data",
            r"\bcall\s+ed25519_verify",
        ],
        "announce_validate validates structure, hashes destination, then verifies signature",
    )
    require(src.count("call    .Lav_copy_bytes") == 5,
            "signed-data copy count must be destination/public/name/random/app")
    require(
        re.search(r"\baddi\s+a3,\s*s0,\s*ANNOUNCE_RX_OFF_PUBLIC_KEY", src)
        and re.search(r"\baddi\s+a3,\s*a3,\s*32", src),
        "Ed25519 public key must be public_key[32:64]",
    )
    require(
        re.search(r"\bli\s+t0,\s*ANNOUNCE_SIGNED_FIXED_LEN", src)
        and re.search(r"\badd\s+a2,\s*t0,\s*s1", src),
        "signature message length must be fixed signed prefix plus app data",
    )


def main() -> None:
    prove_constants()
    prove_shape_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
