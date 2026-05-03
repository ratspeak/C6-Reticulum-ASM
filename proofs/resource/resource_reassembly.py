#!/usr/bin/env python3
"""Finite model/source verifier for milestone-7 resource reassembly update."""

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


EQU = parse_equ(
    "src/include/config.S",
    "src/include/x25519.S",
    "src/include/ed25519.S",
    "src/include/link.S",
    "src/include/resource.S",
)


@dataclasses.dataclass(frozen=True)
class Advertisement:
    resource_hash: bytes
    random_hash: bytes
    hashmap: bytes
    part_count: int


@dataclasses.dataclass
class Entry:
    valid: bool = False
    status: int = 0
    window: int = 0
    total_parts: int = 0
    received_count: int = 0
    consecutive_index: int = 0
    resource_hash: bytes = bytes(32)
    random_hash: bytes = bytes(4)
    bitmap: int = 0
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


def maphash(part: bytes, random_hash: bytes) -> bytes:
    return hashlib.sha256(part + random_hash).digest()[:EQU["RESOURCE_MAPHASH_SIZE"]]


def advertise(table: list[Entry], adv: Advertisement) -> tuple[int, list[Entry]]:
    if adv.part_count == 0 or adv.part_count > EQU["RESOURCE_REASSEMBLY_MAX_PARTS"]:
        return EQU["RESOURCE_ERR_INVAL"], table
    if len(adv.hashmap) != adv.part_count * EQU["RESOURCE_MAPHASH_SIZE"]:
        return EQU["RESOURCE_ERR_INVAL"], table
    for entry in table:
        if entry.valid and entry.resource_hash == adv.resource_hash:
            return EQU["RESOURCE_REASM_RESULT_DUPLICATE"], table
    out = [dataclasses.replace(e) for e in table]
    slot = next((i for i, entry in enumerate(out) if not entry.valid), 0)
    padded_hashmap = adv.hashmap + bytes(EQU["RESOURCE_REASM_HASHMAP_BYTES"] - len(adv.hashmap))
    out[slot] = Entry(
        valid=True,
        status=EQU["RESOURCE_REASM_STATUS_RECEIVING"],
        window=EQU["RESOURCE_REASM_WINDOW_INIT"],
        total_parts=adv.part_count,
        resource_hash=adv.resource_hash,
        random_hash=adv.random_hash,
        hashmap=padded_hashmap,
    )
    return EQU["RESOURCE_REASM_RESULT_ADVERTISED"], out


def update_part(table: list[Entry], part: bytes) -> tuple[int, list[Entry]]:
    out = [dataclasses.replace(e) for e in table]
    for entry in out:
        if not entry.valid or entry.status != EQU["RESOURCE_REASM_STATUS_RECEIVING"]:
            continue
        ph = maphash(part, entry.random_hash)
        start = entry.consecutive_index - 1 if entry.consecutive_index > 0 else 0
        end = min(entry.total_parts, start + entry.window)
        for idx in range(start, end):
            off = idx * EQU["RESOURCE_MAPHASH_SIZE"]
            if entry.hashmap[off:off + EQU["RESOURCE_MAPHASH_SIZE"]] != ph:
                continue
            if entry.bitmap & (1 << idx):
                return EQU["RESOURCE_REASM_RESULT_DUPLICATE"], out
            entry.bitmap |= 1 << idx
            entry.received_count += 1
            while (
                entry.consecutive_index < entry.total_parts
                and entry.bitmap & (1 << entry.consecutive_index)
            ):
                entry.consecutive_index += 1
            if entry.received_count == entry.total_parts:
                entry.status = EQU["RESOURCE_REASM_STATUS_COMPLETE"]
                return EQU["RESOURCE_REASM_RESULT_COMPLETE"], out
            return EQU["RESOURCE_REASM_RESULT_PART_ACCEPTED"], out
    return EQU["RESOURCE_ERR_INVAL"], table


def prove_constants() -> None:
    require(EQU["RESOURCE_REASM_RESULT_ADVERTISED"] == 1, "advertised result")
    require(EQU["RESOURCE_REASM_RESULT_PART_ACCEPTED"] == 2, "part result")
    require(EQU["RESOURCE_REASM_RESULT_DUPLICATE"] == 3, "duplicate result")
    require(EQU["RESOURCE_REASM_RESULT_COMPLETE"] == 4, "complete result")
    require(EQU["RESOURCE_REASM_WINDOW_INIT"] == 4, "initial window")
    require(EQU["RESOURCE_REASM_BITMAP_BYTES"] == 8, "bitmap bytes")
    require(EQU["RESOURCE_REASM_HASHMAP_BYTES"] == 256, "hashmap bytes")


def prove_model() -> None:
    parts = [b"zero", b"one", b"two"]
    random_hash = b"RND0"
    adv = Advertisement(
        resource_hash=bytes(range(32)),
        random_hash=random_hash,
        hashmap=b"".join(maphash(part, random_hash) for part in parts),
        part_count=len(parts),
    )
    table = [Entry() for _ in range(EQU["RESOURCE_REASSEMBLY_CAPACITY"])]
    status, table = advertise(table, adv)
    require(status == EQU["RESOURCE_REASM_RESULT_ADVERTISED"], "advertise status")
    require(table[0].valid and table[0].total_parts == 3, "advertise installed")

    status, table = update_part(table, parts[1])
    require(status == EQU["RESOURCE_REASM_RESULT_PART_ACCEPTED"], "out-of-order accept")
    require(table[0].received_count == 1, "received count after part 1")
    require(table[0].consecutive_index == 0, "consecutive stays at first gap")

    status, table = update_part(table, parts[0])
    require(status == EQU["RESOURCE_REASM_RESULT_PART_ACCEPTED"], "part 0 accept")
    require(table[0].consecutive_index == 2, "consecutive advances through part 1")

    status, table = update_part(table, parts[1])
    require(status == EQU["RESOURCE_REASM_RESULT_DUPLICATE"], "duplicate status")
    require(table[0].received_count == 2, "duplicate did not increment")

    status, table = update_part(table, parts[2])
    require(status == EQU["RESOURCE_REASM_RESULT_COMPLETE"], "complete status")
    require(table[0].status == EQU["RESOURCE_REASM_STATUS_COMPLETE"], "complete entry")
    require(table[0].consecutive_index == 3, "all consecutive")

    status, _ = advertise(table, adv)
    require(status == EQU["RESOURCE_REASM_RESULT_DUPLICATE"], "duplicate advertisement")
    status, _ = update_part(table, b"unknown")
    require(status == EQU["RESOURCE_ERR_INVAL"], "unknown part reject")


def prove_source_shape() -> None:
    src = body(
        "src/resource/resource_reassembly_update.S",
        "resource_reassembly_update",
    )
    ordered(
        src,
        [
            r"\bbnez\s+s0,\s*\.Lrru_advertise",
            r"\bla\s+s3,\s*resource_reassembly_table",
            r"\bli\s+s4,\s*RESOURCE_REASSEMBLY_CAPACITY",
            r"\bcall\s+resource_part_parse",
            r"\blw\s+s9,\s*RESOURCE_REASM_OFF_CONSECUTIVE_IDX\(s3\)",
            r"\blbu\s+t0,\s*RESOURCE_REASM_OFF_WINDOW\(s3\)",
            r"\.Lrru_scan_window:",
            r"\.Lrru_part_match:",
            r"\bsrli\s+t0,\s*s9,\s*3",
            r"\bandi\s+t1,\s*s9,\s*7",
            r"\.Lrru_advance_consecutive:",
            r"\bsw\s+t1,\s*RESOURCE_REASM_OFF_CONSECUTIVE_IDX\(s3\)",
            r"\bli\s+a0,\s*RESOURCE_REASM_RESULT_COMPLETE",
            r"\.Lrru_advertise:",
            r"\blw\s+s7,\s*RESOURCE_ADV_OFF_PART_COUNT\(s0\)",
            r"\bla\s+s3,\s*resource_reassembly_table",
            r"\bcall\s+\.Lrru_memeq",
            r"\.Lrru_adv_install:",
            r"\bcall\s+\.Lrru_clear_bytes",
            r"\bsb\s+t0,\s*RESOURCE_REASM_OFF_VALID\(s5\)",
            r"\bsw\s+s7,\s*RESOURCE_REASM_OFF_TOTAL_PARTS\(s5\)",
            r"\bcall\s+\.Lrru_copy_bytes",
            r"\bli\s+a0,\s*RESOURCE_REASM_RESULT_ADVERTISED",
        ],
        "resource_reassembly_update advertise/part state machine shape",
    )
    require(src.count("call    .Lrru_copy_bytes") == 3,
            "advertise copies hash, random hash, and hashmap")


def main() -> None:
    prove_constants()
    prove_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
