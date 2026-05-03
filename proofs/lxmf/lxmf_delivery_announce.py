#!/usr/bin/env python3
"""Source/contract verifier for LXMF delivery announce app-data."""

from __future__ import annotations

import re
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


def reference_app_data(display_name: bytes | None, stamp_cost: int) -> bytes:
    encoded_name = display_name
    encoded_cost = stamp_cost if 0 < stamp_cost < 255 else None
    return msgpack.packb([encoded_name, encoded_cost])


def local_app_data(display_name: bytes | None, stamp_cost: int) -> bytes:
    out = bytearray([EQU["LXMF_MSGPACK_FIXARRAY2"]])
    if display_name is None:
        out.append(EQU["LXMF_MSGPACK_NIL"])
    else:
        require(len(display_name) <= EQU["LXMF_DELIVERY_ANNOUNCE_MAX_NAME"], "name cap")
        out.extend((EQU["LXMF_MSGPACK_BIN8"], len(display_name)))
        out.extend(display_name)

    if 0 < stamp_cost < 128:
        out.append(stamp_cost)
    elif 128 <= stamp_cost < 255:
        out.extend((EQU["LXMF_MSGPACK_UINT8"], stamp_cost))
    else:
        out.append(EQU["LXMF_MSGPACK_NIL"])
    return bytes(out)


def prove_constants() -> None:
    require(EQU["LXMF_HASH_SIZE"] == 16, "hash size")
    require(EQU["LXMF_SIGNATURE_SIZE"] == 64, "signature size")
    require(EQU["LXMF_OVERHEAD"] == 112, "LXMF overhead")
    require(EQU["LXMF_DELIVERY_ANNOUNCE_MAX_NAME"] == 255, "display name cap")
    require(EQU["LXMF_DELIVERY_ANNOUNCE_MAX_LEN"] == 260, "announce app-data cap")


def prove_vectors() -> None:
    cases = [
        (None, 0, "92c0c0"),
        (b"Test", 0, "92c40454657374c0"),
        (b"Test", 16, "92c4045465737410"),
        (b"Test", 128, "92c40454657374cc80"),
        (b"", 1, "92c40001"),
        (bytes(range(255)), 254, None),
    ]
    for name, cost, expected_hex in cases:
        local = local_app_data(name, cost)
        upstream = reference_app_data(name, cost)
        require(local == upstream, f"upstream mismatch for {name!r}, {cost}")
        if expected_hex is not None:
            require(local.hex() == expected_hex, f"hex mismatch for {name!r}, {cost}")


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_delivery_announce_build.S", "lxmf_delivery_announce_build")
    ordered(
        src,
        [
            r"\bbeqz\s+s3,\s*\.Lldab_invalid",
            r"\bbeqz\s+s0,\s*\.Lldab_name_nil",
            r"\bli\s+t0,\s*LXMF_DELIVERY_ANNOUNCE_MAX_NAME",
            r"\bbltu\s+t0,\s*s1,\s*\.Lldab_overflow",
            r"\bbnez\s+s1,\s*\.Lldab_invalid",
            r"\bli\s+t3,\s*1",
            r"\bli\s+t0,\s*255",
            r"\bbgeu\s+s2,\s*t0,\s*\.Lldab_have_cost_len",
            r"\bli\s+t0,\s*128",
            r"\bbltu\s+s2,\s*t0,\s*\.Lldab_have_cost_len",
            r"\bli\s+t3,\s*2",
            r"\bbltu\s+s4,\s*s5,\s*\.Lldab_overflow",
            r"\bli\s+t0,\s*LXMF_MSGPACK_FIXARRAY2",
            r"\bli\s+t0,\s*LXMF_MSGPACK_BIN8",
            r"\bcall\s+\.Lldab_copy_bytes",
            r"\bli\s+t0,\s*LXMF_MSGPACK_UINT8",
            r"\bli\s+t0,\s*LXMF_MSGPACK_NIL",
        ],
        "validation/encoding order",
    )


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
