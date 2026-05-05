#!/usr/bin/env python3
"""Source/contract verifier for milestone-5 transport_process_announce."""

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
TP = parse_equ("src/include/transport.S")


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


def process_status(parse_ok: bool, valid: bool, lookup_rc: int, update_ok: bool) -> int:
    if not parse_ok or not valid:
        return TP["TRANSPORT_ERR_INVAL"]
    if lookup_rc not in (TP["TRANSPORT_OK"], TP["TRANSPORT_ERR_NOT_FOUND"]):
        return TP["TRANSPORT_ERR_INVAL"]
    if not update_ok:
        return TP["TRANSPORT_ERR_INVAL"]
    return (
        TP["TRANSPORT_STATUS_UPDATED"]
        if lookup_rc == TP["TRANSPORT_OK"]
        else TP["TRANSPORT_STATUS_ACCEPTED"]
    )


def prove_status_model() -> None:
    require(TP["TRANSPORT_STATUS_ACCEPTED"] == 0, "new path status")
    require(TP["TRANSPORT_STATUS_UPDATED"] > 0, "update status is positive")
    require(TP["TRANSPORT_ERR_INVAL"] < 0, "invalid status is negative")
    require(process_status(True, True, TP["TRANSPORT_ERR_NOT_FOUND"], True) == 0,
            "new path status model")
    require(process_status(True, True, TP["TRANSPORT_OK"], True) ==
            TP["TRANSPORT_STATUS_UPDATED"], "updated path status model")
    for args in (
        (False, True, TP["TRANSPORT_ERR_NOT_FOUND"], True),
        (True, False, TP["TRANSPORT_ERR_NOT_FOUND"], True),
        (True, True, TP["TRANSPORT_ERR_INVAL"], True),
        (True, True, TP["TRANSPORT_OK"], False),
    ):
        require(process_status(*args) == TP["TRANSPORT_ERR_INVAL"],
                f"invalid model accepted {args}")


def prove_frame_constants() -> None:
    require(ANN["ANNOUNCE_RX_T_SIZE"] == 180, "parsed struct size")
    require(TP["TRANSPORT_PATH_ENTRY_SIZE"] == 104, "lookup scratch size")
    require(180 + 104 <= 284, "frame scratch layout")


def prove_source_shape() -> None:
    src = body("src/transport/transport_process_announce.S",
               "transport_process_announce")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Ltpa_invalid",
            r"\bcall\s+announce_parse",
            r"\bbnez\s+a0,\s*\.Ltpa_invalid",
            r"\bcall\s+announce_validate",
            r"\bbnez\s+a0,\s*\.Ltpa_invalid",
            r"\bcall\s+transport_path_lookup",
            r"\bli\s+s3,\s*TRANSPORT_STATUS_ACCEPTED",
            r"\bbeq\s+a0,\s*t0,\s*\.Ltpa_update",
            r"\bbnez\s+a0,\s*\.Ltpa_invalid",
            r"\bli\s+s3,\s*TRANSPORT_STATUS_UPDATED",
            r"\.Ltpa_update:",
            r"\blbu\s+a2,\s*ANNOUNCE_RAW_OFF_HOPS\(s0\)",
            r"\baddi\s+a2,\s*a2,\s*1",
            r"\bcall\s+transport_path_update",
            r"\bbnez\s+a0,\s*\.Ltpa_invalid",
            r"\bmv\s+a0,\s*s3",
        ],
        "process announce parse/validate/lookup/update order",
    )


def main() -> None:
    prove_status_model()
    prove_frame_constants()
    prove_source_shape()


if __name__ == "__main__":
    main()
