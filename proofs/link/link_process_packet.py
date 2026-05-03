#!/usr/bin/env python3
"""Source/contract verifier for milestone-6 link_process_packet."""

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
    "src/include/packet.S",
    "src/include/link.S",
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


def classify(packet_type: int, dest_type_bits: int, context: int, known_link: bool) -> int:
    if packet_type == EQU["PKT_LINKREQUEST"]:
        return EQU["LINK_OK"]
    if packet_type == EQU["PKT_ANNOUNCE"]:
        return EQU["LINK_OK"]
    if packet_type != EQU["PKT_DATA"]:
        return EQU["LINK_ERR_INVAL"]
    if dest_type_bits != EQU["LINK_DEST_TYPE_LINK_BITS"]:
        return EQU["LINK_ERR_INVAL"]
    if context != EQU["LINK_DATA_CONTEXT_NONE"]:
        return EQU["LINK_ERR_INVAL"]
    if not known_link:
        return EQU["LINK_ERR_INVAL"]
    return EQU["LINK_STATUS_DECRYPTED"]


def prove_constants() -> None:
    require(EQU["LINK_DATA_HEADER_FLAGS"] == 0x0C, "HEADER_1 link DATA flags")
    require(EQU["LINK_DEST_TYPE_LINK_BITS"] == 0x0C, "link dest-type bits")
    require(EQU["LINK_DATA_CONTEXT_NONE"] == 0, "link data context")
    require(EQU["LINK_STATUS_DECRYPTED"] == 2, "decrypted status")
    require(EQU["LINK_SESSION_TOKEN_OVERHEAD"] == 48, "token overhead")
    require(EQU["LINK_SESSION_TOKEN_MAX"] == 480, "token max")


def prove_classification_model() -> None:
    require(classify(EQU["PKT_LINKREQUEST"], 0, 0, False) == EQU["LINK_OK"],
            "link request classification")
    require(classify(EQU["PKT_ANNOUNCE"], 0, 0, False) == EQU["LINK_OK"],
            "announce classification")
    require(classify(EQU["PKT_DATA"], EQU["LINK_DEST_TYPE_LINK_BITS"], 0, True)
            == EQU["LINK_STATUS_DECRYPTED"], "encrypted link data classification")
    for args in (
        (EQU["PKT_PROOF"], EQU["LINK_DEST_TYPE_LINK_BITS"], 0, True),
        (EQU["PKT_DATA"], 0, 0, True),
        (EQU["PKT_DATA"], EQU["LINK_DEST_TYPE_LINK_BITS"], 1, True),
        (EQU["PKT_DATA"], EQU["LINK_DEST_TYPE_LINK_BITS"], 0, False),
    ):
        require(classify(*args) == EQU["LINK_ERR_INVAL"],
                f"invalid classification accepted {args}")


def prove_source_shape() -> None:
    src = body("src/link/link_process_packet.S", "link_process_packet")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llpp_invalid",
            r"\bcall\s+packet_parse_header",
            r"\blbu\s+t0,\s*LPP_PKT_OFF \+ PKT_OFF_PACKET_TYPE\(sp\)",
            r"\bbeq\s+t0,\s*t1,\s*\.Llpp_link_request",
            r"\bbeq\s+t0,\s*t1,\s*\.Llpp_announce",
            r"\bbne\s+t0,\s*t1,\s*\.Llpp_invalid",
            r"\blbu\s+t0,\s*LPP_PKT_OFF \+ PKT_OFF_HEADER_TYPE\(sp\)",
            r"\bandi\s+t0,\s*t0,\s*MASK_DEST_TYPE",
            r"\bli\s+t1,\s*LINK_DEST_TYPE_LINK_BITS",
            r"\blhu\s+s5,\s*LPP_PKT_OFF \+ PKT_OFF_PAYLOAD_LEN\(sp\)",
            r"\bli\s+t0,\s*LINK_SESSION_TOKEN_OVERHEAD \+ 17",
            r"\blbu\s+t2,\s*0\(s3\)",
            r"\bli\s+t3,\s*LINK_DATA_CONTEXT_NONE",
            r"\.Llpp_scan:",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_VALID\(s7\)",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_STATUS\(s7\)",
            r"\bcall\s+\.Llpp_memeq",
            r"\.Llpp_found:",
            r"\bcall\s+link_session_decrypt",
            r"\bli\s+a0,\s*LINK_STATUS_DECRYPTED",
            r"\.Llpp_link_request:",
            r"\bcall\s+link_request_parse",
            r"\bcall\s+link_handshake_accept",
            r"\.Llpp_announce:",
            r"\bcall\s+transport_process_announce",
        ],
        "dispatch parse/classify/link-request/announce/data order",
    )
    require(src.count("call    packet_parse_header") == 1, "packet_parse_header count")
    require(src.count("call    link_request_parse") == 1, "link_request_parse count")
    require(src.count("call    link_handshake_accept") == 1, "link_handshake_accept count")
    require(src.count("call    link_session_decrypt") == 1, "link_session_decrypt count")
    require(src.count("call    transport_process_announce") == 1,
            "transport_process_announce count")


def main() -> None:
    prove_constants()
    prove_classification_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
