#!/usr/bin/env python3
"""Finite model/source verifier for the milestone-5 transport path table."""

from __future__ import annotations

import dataclasses
import hashlib
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


TP = parse_equ("src/include/transport.S")


@dataclasses.dataclass(frozen=True)
class Ann:
    dest_hash: bytes
    public_key: bytes

    @property
    def identity_hash(self) -> bytes:
        return hashlib.sha256(self.public_key).digest()[:16]


@dataclasses.dataclass
class Entry:
    valid: bool = False
    interface_id: int = 0
    hops: int = 0
    last_seen: int = 0
    dest_hash: bytes = bytes(16)
    identity_hash: bytes = bytes(16)
    public_key: bytes = bytes(64)
    next_hop: bytes = bytes(16)


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


def make_ann(seed: int) -> Ann:
    return Ann(
        dest_hash=bytes((seed + i * 7) & 0xFF for i in range(16)),
        public_key=bytes((seed + 0x40 + i * 11) & 0xFF for i in range(64)),
    )


def path_init(table: list[Entry]) -> list[Entry]:
    return [Entry() for _ in table]


def path_lookup(table: list[Entry], dest_hash: bytes) -> Entry | None:
    for entry in table:
        if entry.valid and entry.dest_hash == dest_hash:
            return Entry(**dataclasses.asdict(entry))
    return None


def path_update(
    table: list[Entry], ann: Ann, interface_id: int, hops: int, now: int,
    next_hop: bytes | None = None,
) -> list[Entry]:
    require(0 < interface_id < 256, "interface id byte")
    require(0 <= hops < 256, "hops byte")
    out = [Entry(**dataclasses.asdict(e)) for e in table]

    selected: int | None = None
    first_invalid: int | None = None
    oldest: int | None = None
    oldest_age = -1
    for idx, entry in enumerate(out):
        if entry.valid:
            if entry.dest_hash == ann.dest_hash:
                selected = idx
                break
            age = (now - entry.last_seen) & 0xFFFFFFFF
            if oldest is None or age > oldest_age:
                oldest = idx
                oldest_age = age
        elif first_invalid is None:
            first_invalid = idx
    if selected is None:
        selected = first_invalid if first_invalid is not None else oldest
    require(selected is not None, "capacity must be nonzero")

    out[selected] = Entry(
        valid=True,
        interface_id=interface_id,
        hops=hops,
        last_seen=now & 0xFFFFFFFF,
        dest_hash=ann.dest_hash,
        identity_hash=ann.identity_hash,
        public_key=ann.public_key,
        next_hop=next_hop or ann.dest_hash,
    )
    return out


def prove_constants() -> None:
    require(TP["TRANSPORT_PATH_CAPACITY"] == 8, "capacity")
    require(TP["TRANSPORT_PATH_ENTRY_SIZE"] == 120, "entry size")
    require(TP["TRANSPORT_PATH_TABLE_SIZE"] == 960, "table size")
    require(TP["TRANSPORT_PATH_TABLE_SIZE"] ==
            TP["TRANSPORT_PATH_CAPACITY"] * TP["TRANSPORT_PATH_ENTRY_SIZE"],
            "table size product")
    require(TP["TRANSPORT_PATH_OFF_PUBLIC_KEY"] + 64 ==
            TP["TRANSPORT_PATH_OFF_NEXT_HOP"],
            "public key ends before next hop")
    require(TP["TRANSPORT_PATH_OFF_NEXT_HOP"] + 16 ==
            TP["TRANSPORT_PATH_ENTRY_SIZE"],
            "next hop ends at entry size")


def prove_model() -> None:
    table = path_init([Entry(valid=True) for _ in range(TP["TRANSPORT_PATH_CAPACITY"])])
    require(all(not e.valid for e in table), "init clears valid bits")

    anns = [make_ann(i) for i in range(TP["TRANSPORT_PATH_CAPACITY"] + 1)]
    table = path_update(table, anns[0], 1, 3, 100)
    got = path_lookup(table, anns[0].dest_hash)
    require(got is not None and got.hops == 3 and got.last_seen == 100,
            "insert lookup")
    require(got is not None and got.next_hop == anns[0].dest_hash,
            "default next hop")

    replacement = Ann(anns[0].dest_hash, make_ann(99).public_key)
    custom_next_hop = bytes(range(0xA0, 0xB0))
    table = path_update(table, replacement, 1, 5, 110, custom_next_hop)
    require(sum(1 for e in table if e.valid) == 1, "existing update duplicated entry")
    got = path_lookup(table, anns[0].dest_hash)
    require(got is not None and got.hops == 5 and got.public_key == replacement.public_key,
            "existing update failed")
    require(got is not None and got.next_hop == custom_next_hop, "custom next hop")

    table = path_init(table)
    for idx in range(TP["TRANSPORT_PATH_CAPACITY"]):
        table = path_update(table, anns[idx], 1, idx, 100 + idx * 10)
    table = path_update(table, anns[8], 1, 8, 180)
    require(path_lookup(table, anns[0].dest_hash) is None, "oldest entry not evicted")
    require(path_lookup(table, anns[8].dest_hash) is not None, "new entry missing")
    require(sum(1 for e in table if e.valid) == TP["TRANSPORT_PATH_CAPACITY"],
            "eviction changed capacity")


def prove_source_shape() -> None:
    init = body("src/transport/transport_path_init.S", "transport_path_init")
    ordered(
        init,
        [
            r"\bla\s+t0,\s*transport_path_table",
            r"\bli\s+t1,\s*TRANSPORT_PATH_TABLE_SIZE",
            r"\bsb\s+zero,\s*0\(t0\)",
            r"\bli\s+a0,\s*TRANSPORT_OK",
        ],
        "transport_path_init clears table",
    )

    update = body("src/transport/transport_path_update.S", "transport_path_update")
    ordered(
        update,
        [
            r"\bmv\s+s10,\s*a3",
            r"\bbeqz\s+s0,\s*\.Ltpu_fail",
            r"\bbeqz\s+s1,\s*\.Ltpu_fail",
            r"\bcall\s+identity_hash",
            r"\bcall\s+clock_now_ms",
            r"\bla\s+s4,\s*transport_path_table",
            r"\.Ltpu_scan:",
            r"\bbeqz\s+s8,\s*\.Ltpu_choose_slot",
            r"\bbeqz\s+t0,\s*\.Ltpu_invalid_slot",
            r"\bbeqz\s+t4,\s*\.Ltpu_found_existing",
            r"\bbltu\s+s7,\s*t2,\s*\.Ltpu_set_oldest",
            r"\.Ltpu_choose_slot:",
            r"\.Ltpu_write_entry:",
            r"\bsb\s+t0,\s*TRANSPORT_PATH_OFF_VALID\(s9\)",
            r"\bsw\s+s3,\s*TRANSPORT_PATH_OFF_LAST_SEEN\(s9\)",
            r"\bTRANSPORT_PATH_OFF_NEXT_HOP",
        ],
        "transport_path_update scans, chooses, and writes deterministically",
    )
    require(update.count("call    .Ltpu_copy_bytes") == 4,
            "update must copy dest, identity hash, public key, and next hop")

    lookup = body("src/transport/transport_path_lookup.S", "transport_path_lookup")
    ordered(
        lookup,
        [
            r"\bbeqz\s+s0,\s*\.Ltpl_fail",
            r"\bbeqz\s+s1,\s*\.Ltpl_fail",
            r"\bla\s+s2,\s*transport_path_table",
            r"\.Ltpl_scan:",
            r"\bbeqz\s+s3,\s*\.Ltpl_missing",
            r"\bbeqz\s+t0,\s*\.Ltpl_next",
            r"\bcall\s+\.Ltpl_memeq",
            r"\bbeqz\s+a0,\s*\.Ltpl_found",
            r"\bcall\s+\.Ltpl_copy_bytes",
        ],
        "transport_path_lookup searches only valid entries and copies one hit",
    )


def main() -> None:
    prove_constants()
    prove_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
