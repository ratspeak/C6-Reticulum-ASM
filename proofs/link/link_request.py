#!/usr/bin/env python3
"""Finite bounds/source verifier for milestone-6 link request build/parse."""

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


LINK = parse_equ(
    "src/include/config.S",
    "src/include/x25519.S",
    "src/include/ed25519.S",
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


def accepts(
    length: int,
    flags: int,
    context: int,
    signal0: int,
    signal1: int,
    signal2: int,
) -> bool:
    return (
        length == LINK["LINK_REQUEST_RAW_LEN"]
        and length <= LINK["LINK_REQUEST_RETICULUM_MDU"]
        and flags == LINK["LINK_REQUEST_HEADER_FLAGS"]
        and context == LINK["LINK_REQUEST_CONTEXT_NONE"]
        and signal0 == LINK["LINK_SIGNAL_BYTE0"]
        and signal1 == LINK["LINK_SIGNAL_BYTE1"]
        and signal2 == LINK["LINK_SIGNAL_BYTE2"]
    )


def prove_constants() -> None:
    require(LINK["LINK_HEADER_LEN"] == 19, "HEADER_1 link header length")
    require(LINK["LINK_X25519_PUB_SIZE"] == 32, "x25519 public size")
    require(LINK["LINK_ED25519_PUB_SIZE"] == 32, "ed25519 public size")
    require(LINK["LINK_SIGNAL_SIZE"] == 3, "signalling size")
    require(LINK["LINK_REQUEST_PAYLOAD_LEN"] == 67, "current payload length")
    require(LINK["LINK_REQUEST_RAW_LEN"] == 86, "current raw packet length")
    require(LINK["LINK_REQUEST_RAW_LEN"] <= LINK["LINK_REQUEST_RETICULUM_MDU"],
            "link request fits MDU")
    require(LINK["LINK_SIGNAL_BYTE0"] == 0x20, "default mode signalling byte")
    require(LINK["LINK_SIGNAL_BYTE1"] == 0x01, "default MTU high byte")
    require(LINK["LINK_SIGNAL_BYTE2"] == 0xF4, "default MTU low byte")
    require(LINK["LINK_DEFAULT_MTU"] == 500, "default Reticulum MTU")
    require(LINK["LINK_MODE_AES256_CBC"] == 1, "AES-256-CBC mode")
    require(LINK["LINK_REQUEST_T_SIZE"] == 92, "parsed struct size")
    require(LINK["LINK_ERR_INVAL"] < 0, "invalid status negative")
    require(LINK["LINK_ERR_OVERFLOW"] < 0, "overflow status negative")


def prove_acceptance_domain() -> None:
    for length in range(0, LINK["LINK_REQUEST_RETICULUM_MDU"] + 2):
        good = accepts(
            length,
            LINK["LINK_REQUEST_HEADER_FLAGS"],
            LINK["LINK_REQUEST_CONTEXT_NONE"],
            LINK["LINK_SIGNAL_BYTE0"],
            LINK["LINK_SIGNAL_BYTE1"],
            LINK["LINK_SIGNAL_BYTE2"],
        )
        require(
            good == (length == LINK["LINK_REQUEST_RAW_LEN"]),
            f"length predicate mismatch at {length}",
        )
        require(
            not accepts(length, 0x00, 0x00, 0x20, 0x01, 0xF4),
            f"bad flags accepted at {length}",
        )
        require(
            not accepts(length, 0x02, 0x01, 0x20, 0x01, 0xF4),
            f"bad context accepted at {length}",
        )
        require(
            not accepts(length, 0x02, 0x00, 0x40, 0x01, 0xF4),
            f"bad mode accepted at {length}",
        )
        require(
            not accepts(length, 0x02, 0x00, 0x20, 0x01, 0xF5),
            f"bad MTU accepted at {length}",
        )


def prove_field_ranges() -> None:
    ranges = (
        ("destination_hash", LINK["LINK_REQUEST_RAW_OFF_DEST_HASH"],
         LINK["LINK_DESTINATION_HASH_SIZE"]),
        ("x25519_public", LINK["LINK_REQUEST_RAW_OFF_X25519_PUB"],
         LINK["LINK_X25519_PUB_SIZE"]),
        ("ed25519_public", LINK["LINK_REQUEST_RAW_OFF_ED25519_PUB"],
         LINK["LINK_ED25519_PUB_SIZE"]),
        ("signal0", LINK["LINK_REQUEST_RAW_OFF_SIGNAL0"], 1),
        ("signal1", LINK["LINK_REQUEST_RAW_OFF_SIGNAL1"], 1),
        ("signal2", LINK["LINK_REQUEST_RAW_OFF_SIGNAL2"], 1),
    )
    for name, off, size in ranges:
        require(
            off + size <= LINK["LINK_REQUEST_RAW_LEN"],
            f"{name} overruns accepted raw packet",
        )
    struct_ranges = (
        ("dest_hash", LINK["LINK_REQUEST_OFF_DEST_HASH"],
         LINK["LINK_DESTINATION_HASH_SIZE"]),
        ("x25519", LINK["LINK_REQUEST_OFF_X25519_PUB"],
         LINK["LINK_X25519_PUB_SIZE"]),
        ("ed25519", LINK["LINK_REQUEST_OFF_ED25519_PUB"],
         LINK["LINK_ED25519_PUB_SIZE"]),
    )
    for name, off, size in struct_ranges:
        require(off + size <= LINK["LINK_REQUEST_T_SIZE"],
                f"{name} overruns parsed struct")


def prove_build_source_shape() -> None:
    src = body("src/link/link_request_build.S", "link_request_build")
    ordered(
        src,
        [
            r"\bbeqz\s+a0,\s*\.Llrb_invalid",
            r"\bbeqz\s+a1,\s*\.Llrb_invalid",
            r"\bbeqz\s+a2,\s*\.Llrb_invalid",
            r"\bbeqz\s+a3,\s*\.Llrb_invalid",
            r"\bli\s+t0,\s*LINK_REQUEST_RAW_LEN",
            r"\bbltu\s+a4,\s*t0,\s*\.Llrb_overflow",
            r"\bli\s+t1,\s*LINK_REQUEST_HEADER_FLAGS",
            r"\bsb\s+t1,\s*LINK_REQUEST_RAW_OFF_FLAGS\(a3\)",
            r"\bsb\s+zero,\s*LINK_REQUEST_RAW_OFF_HOPS\(a3\)",
            r"\bsb\s+zero,\s*LINK_REQUEST_RAW_OFF_CONTEXT\(a3\)",
            r"\.Llrb_copy_dest:",
            r"\.Llrb_copy_x25519:",
            r"\.Llrb_copy_ed25519:",
            r"\bli\s+t1,\s*LINK_SIGNAL_BYTE0",
            r"\bli\s+t1,\s*LINK_SIGNAL_BYTE1",
            r"\bli\s+t1,\s*LINK_SIGNAL_BYTE2",
            r"\bli\s+a0,\s*LINK_REQUEST_RAW_LEN",
        ],
        "link_request_build validates and emits fields in order",
    )

    before_capacity = src[: src.index("bltu    a4, t0, .Llrb_overflow")]
    require(
        not re.search(r"\bsb\s+\w+,\s*[^\n]*\(a3\)", before_capacity),
        "link_request_build writes output before capacity check",
    )


def prove_parse_source_shape() -> None:
    src = body("src/link/link_request_parse.S", "link_request_parse")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llrp_fail",
            r"\bbeqz\s+s2,\s*\.Llrp_fail",
            r"\bli\s+t0,\s*LINK_REQUEST_RAW_LEN",
            r"\bbltu\s+s1,\s*t0,\s*\.Llrp_fail",
            r"\bli\s+t0,\s*LINK_REQUEST_RETICULUM_MDU",
            r"\bbltu\s+t0,\s*s1,\s*\.Llrp_fail",
            r"\bli\s+t0,\s*LINK_REQUEST_RAW_LEN",
            r"\bbne\s+s1,\s*t0,\s*\.Llrp_fail",
            r"\bcall\s+packet_parse_header",
            r"\blbu\s+t0,\s*LRP_PKT_OFF \+ PKT_OFF_HEADER_TYPE\(sp\)",
            r"\bbnez\s+t0,\s*\.Llrp_fail",
            r"\blbu\s+t0,\s*LRP_PKT_OFF \+ PKT_OFF_PACKET_TYPE\(sp\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llrp_fail",
            r"\blbu\s+t0,\s*LINK_REQUEST_RAW_OFF_FLAGS\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llrp_fail",
            r"\blbu\s+t0,\s*LINK_REQUEST_RAW_OFF_CONTEXT\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llrp_fail",
            r"\blbu\s+t0,\s*LINK_REQUEST_RAW_OFF_SIGNAL0\(s0\)",
            r"\blbu\s+t0,\s*LINK_REQUEST_RAW_OFF_SIGNAL1\(s0\)",
            r"\blbu\s+t0,\s*LINK_REQUEST_RAW_OFF_SIGNAL2\(s0\)",
            r"\bsw\s+s1,\s*LINK_REQUEST_OFF_RAW_LEN\(s2\)",
        ],
        "link_request_parse validates before output",
    )
    before_output = src[: src.index("sw      s1, LINK_REQUEST_OFF_RAW_LEN(s2)")]
    require(
        not re.search(r"\b(?:sb|sh|sw)\s+\w+,\s*[^\n]*\(s2\)", before_output),
        "link_request_parse writes output before validation completes",
    )
    require(src.count("call    .Llrp_copy_bytes") == 3, "fixed-field copy count")


def main() -> None:
    prove_constants()
    prove_acceptance_domain()
    prove_field_ranges()
    prove_build_source_shape()
    prove_parse_source_shape()


if __name__ == "__main__":
    main()
