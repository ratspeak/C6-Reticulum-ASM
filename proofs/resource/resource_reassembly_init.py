#!/usr/bin/env python3
"""Source/contract verifier for milestone-7 resource reassembly init."""

from __future__ import annotations

import dataclasses
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


@dataclasses.dataclass
class ReassemblyEntry:
    valid: int = 0
    status: int = 0
    window: int = 0
    total_parts: int = 0
    received_count: int = 0
    consecutive_index: int = 0
    resource_hash: bytes = bytes(32)
    random_hash: bytes = bytes(4)
    received_bitmap: bytes = bytes(8)
    hashmap: bytes = bytes(256)


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


def reassembly_init(table: list[ReassemblyEntry]) -> list[ReassemblyEntry]:
    return [ReassemblyEntry() for _ in table]


def prove_constants() -> None:
    require(EQU["RESOURCE_HASH_SIZE"] == 32, "resource hash size")
    require(EQU["RESOURCE_RANDOM_HASH_SIZE"] == 4, "random hash size")
    require(EQU["RESOURCE_MAPHASH_SIZE"] == 4, "map-hash size")
    require(EQU["RESOURCE_REASSEMBLY_CAPACITY"] == 2, "capacity")
    require(EQU["RESOURCE_REASSEMBLY_MAX_PARTS"] == 64, "max parts")
    require(EQU["RESOURCE_REASM_BITMAP_BYTES"] == 8, "bitmap bytes")
    require(EQU["RESOURCE_REASM_HASHMAP_BYTES"] == 256, "hashmap bytes")
    require(EQU["RESOURCE_REASM_WINDOW_MIN"] == 2, "window min")
    require(EQU["RESOURCE_REASM_WINDOW_INIT"] == 4, "initial window")
    require(EQU["RESOURCE_REASM_WINDOW_MAX"] == 75, "window max")
    require(EQU["RESOURCE_REASM_STATUS_EMPTY"] == 0, "empty status")
    require(EQU["RESOURCE_REASM_STATUS_RECEIVING"] == 1, "receiving status")
    require(EQU["RESOURCE_REASM_STATUS_COMPLETE"] == 2, "complete status")
    require(
        EQU["RESOURCE_REASM_OFF_RESOURCE_HASH"] + EQU["RESOURCE_HASH_SIZE"]
        == EQU["RESOURCE_REASM_OFF_RANDOM_HASH"],
        "resource hash ends at random hash",
    )
    require(
        EQU["RESOURCE_REASM_OFF_RANDOM_HASH"] + EQU["RESOURCE_RANDOM_HASH_SIZE"]
        == EQU["RESOURCE_REASM_OFF_RECEIVED_BITMAP"],
        "random hash ends at bitmap",
    )
    require(
        EQU["RESOURCE_REASM_OFF_RECEIVED_BITMAP"] + EQU["RESOURCE_REASM_BITMAP_BYTES"]
        == EQU["RESOURCE_REASM_OFF_HASHMAP"],
        "bitmap ends at hashmap",
    )
    require(
        EQU["RESOURCE_REASM_OFF_HASHMAP"] + EQU["RESOURCE_REASM_HASHMAP_BYTES"]
        == EQU["RESOURCE_REASM_ENTRY_SIZE"],
        "hashmap ends at entry size",
    )
    require(
        EQU["RESOURCE_REASM_TABLE_SIZE"]
        == EQU["RESOURCE_REASSEMBLY_CAPACITY"] * EQU["RESOURCE_REASM_ENTRY_SIZE"],
        "table size product",
    )


def prove_model() -> None:
    table = [
        ReassemblyEntry(
            valid=1,
            status=EQU["RESOURCE_REASM_STATUS_RECEIVING"],
            window=EQU["RESOURCE_REASM_WINDOW_INIT"],
            total_parts=17,
            received_count=3,
            consecutive_index=2,
            resource_hash=bytes([0x11]) * 32,
            random_hash=bytes([0x22]) * 4,
            received_bitmap=bytes([0x80]) + bytes(7),
            hashmap=bytes([0x33]) * 256,
        )
        for _ in range(EQU["RESOURCE_REASSEMBLY_CAPACITY"])
    ]
    cleared = reassembly_init(table)
    require(len(cleared) == EQU["RESOURCE_REASSEMBLY_CAPACITY"], "capacity preserved")
    for entry in cleared:
        require(entry == ReassemblyEntry(), "entry not cleared")


def prove_source_shape() -> None:
    state = read("src/state/resource.S")
    require(".global resource_reassembly_table" in state, "table global")
    require(".skip   RESOURCE_REASM_TABLE_SIZE" in state, "table allocation")
    require(
        ".size   resource_reassembly_table, RESOURCE_REASM_TABLE_SIZE" in state,
        "table size annotation",
    )

    src = body("src/resource/resource_reassembly_init.S", "resource_reassembly_init")
    ordered(
        src,
        [
            r"\bla\s+t0,\s*resource_reassembly_table",
            r"\bli\s+t1,\s*RESOURCE_REASM_TABLE_SIZE",
            r"\bsb\s+zero,\s*0\(t0\)",
            r"\baddi\s+t0,\s*t0,\s*1",
            r"\baddi\s+t1,\s*t1,\s*-1",
            r"\bbnez\s+t1,\s*\.Lrri_clear",
            r"\bli\s+a0,\s*RESOURCE_OK",
        ],
        "resource_reassembly_init clears fixed table",
    )


def main() -> None:
    prove_constants()
    prove_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
