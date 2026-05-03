#!/usr/bin/env python3
"""Source/contract verifier for milestone-6 link_handshake_init."""

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


def choose_slot(
    table: list[tuple[bool, bytes, int]],
    dest: bytes,
    now: int,
) -> int:
    first_invalid: int | None = None
    oldest: int | None = None
    oldest_age = -1
    for idx, (valid, entry_dest, last_seen) in enumerate(table):
        if not valid:
            if first_invalid is None:
                first_invalid = idx
            continue
        if entry_dest == dest:
            return idx
        age = (now - last_seen) & 0xFFFFFFFF
        if oldest is None or age > oldest_age:
            oldest = idx
            oldest_age = age
    if first_invalid is not None:
        return first_invalid
    require(oldest is not None, "non-empty table has no eviction candidate")
    return oldest


def prove_constants() -> None:
    require(LINK["LINK_TABLE_CAPACITY"] == 4, "link table capacity")
    require(LINK["LINK_STATUS_PENDING"] == 1, "pending status")
    require(LINK["LINK_STATUS_ESTABLISHED"] == 2, "established status")
    require(LINK["LINK_ENTRY_OFF_VALID"] == 0, "valid offset")
    require(LINK["LINK_ENTRY_OFF_STATUS"] == 1, "status offset")
    require(LINK["LINK_ENTRY_OFF_LAST_SEEN"] == 4, "last_seen offset")
    require(LINK["LINK_ENTRY_OFF_DEST_HASH"] == 8, "dest offset")
    require(LINK["LINK_ENTRY_OFF_LOCAL_X25519_PUB"] == 24, "x25519 pub offset")
    require(LINK["LINK_ENTRY_OFF_LOCAL_X25519_SK"] == 56, "x25519 sk offset")
    require(LINK["LINK_ENTRY_OFF_LOCAL_ED25519_PUB"] == 88, "ed25519 pub offset")
    require(LINK["LINK_ENTRY_OFF_LOCAL_ED25519_SK"] == 120, "ed25519 sk offset")
    require(LINK["LINK_ENTRY_OFF_KEY_MATERIAL"] == 232, "key material offset")
    require(LINK["LINK_ENTRY_SIZE"] == 296, "link entry size")
    require(LINK["LINK_TABLE_SIZE"] == 1184, "link table size")
    require(LINK["LINK_ERR_INVAL"] < 0, "invalid status negative")
    require(LINK["LINK_ERR_OVERFLOW"] < 0, "overflow status negative")


def prove_slot_model() -> None:
    a = bytes([1]) * 16
    b = bytes([2]) * 16
    c = bytes([3]) * 16
    z = bytes([9]) * 16
    table = [(False, b"", 0), (True, a, 10), (True, b, 20), (False, b"", 0)]
    require(choose_slot(table, a, 50) == 1, "existing destination priority")
    require(choose_slot(table, c, 50) == 0, "first invalid priority")
    full = [(True, bytes([i]) * 16, 100 + i * 10) for i in range(4)]
    require(choose_slot(full, z, 200) == 0, "oldest eviction")
    wrap = [
        (True, bytes([1]) * 16, 0xFFFFFFF0),
        (True, bytes([2]) * 16, 10),
        (True, bytes([3]) * 16, 20),
        (True, bytes([4]) * 16, 30),
    ]
    require(choose_slot(wrap, z, 40) == 0, "unsigned wrap-age eviction")


def prove_source_shape() -> None:
    src = body("src/link/link_handshake_init.S", "link_handshake_init")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llhi_invalid",
            r"\bbeqz\s+s1,\s*\.Llhi_invalid",
            r"\bli\s+t0,\s*LINK_REQUEST_RAW_LEN",
            r"\bbltu\s+s2,\s*t0,\s*\.Llhi_overflow",
            r"\bcall\s+clock_now_ms",
            r"\bla\s+s8,\s*link_table",
            r"\bli\s+s9,\s*LINK_TABLE_CAPACITY",
            r"\.Llhi_scan:",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_VALID\(s8\)",
            r"\bbeqz\s+t0,\s*\.Llhi_invalid_slot",
            r"\.Llhi_cmp_dest:",
            r"\bbne\s+t4,\s*t5,\s*\.Llhi_not_same_dest",
            r"\bmv\s+s3,\s*s8",
            r"\.Llhi_not_same_dest:",
            r"\blw\s+t4,\s*LINK_ENTRY_OFF_LAST_SEEN\(s8\)",
            r"\bsub\s+t5,\s*s7,\s*t4",
            r"\.Llhi_invalid_slot:",
            r"\bmv\s+s4,\s*s8",
            r"\.Llhi_pick:",
            r"\bmv\s+s3,\s*s5",
            r"\.Llhi_have_entry:",
            r"\bcall\s+x25519_keypair",
            r"\bcall\s+ed25519_keypair",
            r"\bsw\s+s7,\s*LINK_ENTRY_OFF_LAST_SEEN\(s3\)",
            r"\bsb\s+t0,\s*LINK_ENTRY_OFF_STATUS\(s3\)",
            r"\bsb\s+t0,\s*LINK_ENTRY_OFF_MODE\(s3\)",
            r"\bcall\s+\.Llhi_copy_bytes",
            r"\bcall\s+\.Llhi_zero_bytes",
            r"\bsb\s+t0,\s*LINK_ENTRY_OFF_VALID\(s3\)",
            r"\bcall\s+link_request_build",
        ],
        "link_handshake_init validate/scan/generate/store/build order",
    )
    first_keygen = src.index("call    x25519_keypair")
    before_keygen = src[:first_keygen]
    require(
        "call    link_request_build" not in before_keygen,
        "request build occurs before key generation",
    )
    first_valid_store = src.index("sb      t0, LINK_ENTRY_OFF_VALID(s3)")
    require(first_valid_store > src.index("call    ed25519_keypair"),
            "entry marked valid before keypair generation")
    require(src.count("call    x25519_keypair") == 1, "x25519 keypair count")
    require(src.count("call    ed25519_keypair") == 1, "ed25519 keypair count")
    require(src.count("call    link_request_build") == 1, "request build count")


def main() -> None:
    prove_constants()
    prove_slot_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
