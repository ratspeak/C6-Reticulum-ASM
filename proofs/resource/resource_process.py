#!/usr/bin/env python3
"""Source/contract verifier for milestone-7 resource plaintext dispatch."""

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


def process_model(context: int, ok: bool = True) -> int:
    if context == EQU["RESOURCE_CONTEXT_CHANNEL"]:
        return EQU["RESOURCE_PROCESS_STATUS_CHANNEL"] if ok else EQU["RESOURCE_ERR_INVAL"]
    if context == EQU["RESOURCE_CONTEXT_RESOURCE_ADV"]:
        return EQU["RESOURCE_REASM_RESULT_ADVERTISED"] if ok else EQU["RESOURCE_ERR_INVAL"]
    if context == EQU["RESOURCE_CONTEXT_RESOURCE"]:
        return EQU["RESOURCE_REASM_RESULT_PART_ACCEPTED"] if ok else EQU["RESOURCE_ERR_INVAL"]
    return EQU["RESOURCE_ERR_INVAL"]


def prove_constants() -> None:
    require(EQU["RESOURCE_CONTEXT_RESOURCE"] == 0x01, "resource context")
    require(EQU["RESOURCE_CONTEXT_RESOURCE_ADV"] == 0x02, "resource adv context")
    require(EQU["RESOURCE_CONTEXT_CHANNEL"] == 0x0E, "channel context")
    require(EQU["RESOURCE_PROCESS_STATUS_CHANNEL"] == 5, "channel status")


def prove_model() -> None:
    require(process_model(0x0E) == 5, "channel accept")
    require(process_model(0x02) == 1, "advertisement accept")
    require(process_model(0x01) == 2, "resource part accept")
    require(process_model(0x7E) == -1, "unknown context reject")
    require(process_model(0x0E, ok=False) == -1, "delegate reject propagates")


def prove_source_shape() -> None:
    src = body(
        "src/resource/resource_process_plaintext.S",
        "resource_process_plaintext",
    )
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Lrpproc_invalid",
            r"\bli\s+t0,\s*RESOURCE_CONTEXT_CHANNEL",
            r"\bbeq\s+s1,\s*t0,\s*\.Lrpproc_channel",
            r"\bli\s+t0,\s*RESOURCE_CONTEXT_RESOURCE_ADV",
            r"\bbeq\s+s1,\s*t0,\s*\.Lrpproc_resource_adv",
            r"\bli\s+t0,\s*RESOURCE_CONTEXT_RESOURCE",
            r"\bbeq\s+s1,\s*t0,\s*\.Lrpproc_resource_part",
            r"\.Lrpproc_channel:",
            r"\bcall\s+channel_envelope_parse",
            r"\bli\s+a0,\s*RESOURCE_PROCESS_STATUS_CHANNEL",
            r"\.Lrpproc_resource_adv:",
            r"\bcall\s+resource_advertisement_parse",
            r"\bcall\s+resource_reassembly_update",
            r"\.Lrpproc_resource_part:",
            r"\bcall\s+resource_reassembly_update",
            r"\.Lrpproc_invalid:",
            r"\bli\s+a0,\s*RESOURCE_ERR_INVAL",
        ],
        "resource_process_plaintext dispatches contexts to verified helpers",
    )
    require(src.count("call    resource_reassembly_update") == 2,
            "advertisement and resource part both update reassembly")


def main() -> None:
    prove_constants()
    prove_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
