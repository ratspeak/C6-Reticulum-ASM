#!/usr/bin/env python3
"""Verifier for the milestone-4 identity persistence record contract."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class ProofError(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


def read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def parse_equ(path: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read(path).splitlines():
        m = re.match(
            r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))",
            line,
        )
        if m:
            values[m.group(1)] = int(m.group(2), 0)
    return values


IDENTITY = parse_equ("src/include/identity.S")
FLASH = parse_equ("src/include/flash.S")


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


def make_identity(seed: int) -> bytes:
    private_key = bytes((seed + i * 3) & 0xFF for i in range(64))
    public_key = bytes((seed + 0x80 + i * 5) & 0xFF for i in range(64))
    identity_hash = hashlib.sha256(public_key).digest()[:16]
    return private_key + public_key + identity_hash + bytes(16)


def make_record(identity: bytes) -> bytes:
    require(len(identity) == IDENTITY["IDENTITY_T_SIZE"], "identity size")
    out = bytearray([0xFF] * IDENTITY["IDENTITY_RECORD_SIZE"])
    out[0:4] = b"RID1"
    out[4] = IDENTITY["IDENTITY_RECORD_VERSION"]
    out[5] = IDENTITY["IDENTITY_RECORD_FLAGS"]
    out[6:8] = IDENTITY["IDENTITY_RECORD_HEADER_LEN"].to_bytes(2, "little")
    out[8:12] = IDENTITY["IDENTITY_T_SIZE"].to_bytes(4, "little")
    out[12:16] = bytes(4)
    out[48:208] = identity
    out[16:48] = hashlib.sha256(bytes(out[0:16]) + identity).digest()
    return bytes(out)


def load_record(record: bytes) -> tuple[int, bytes | None]:
    if record == b"\xff" * IDENTITY["IDENTITY_RECORD_SIZE"]:
        return IDENTITY["IDENTITY_ERR_MISSING"], None
    if record[0:4] != b"RID1":
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if record[4] != IDENTITY["IDENTITY_RECORD_VERSION"]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if record[5] != IDENTITY["IDENTITY_RECORD_FLAGS"]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if int.from_bytes(record[6:8], "little") != IDENTITY["IDENTITY_RECORD_HEADER_LEN"]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if int.from_bytes(record[8:12], "little") != IDENTITY["IDENTITY_T_SIZE"]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if record[12:16] != bytes(4):
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if record[208:256] != b"\xff" * 48:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    identity = record[48:208]
    if hashlib.sha256(record[0:16] + identity).digest() != record[16:48]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    if hashlib.sha256(identity[64:128]).digest()[:16] != identity[128:144]:
        return IDENTITY["IDENTITY_ERR_INVAL"], None
    return IDENTITY["IDENTITY_OK"], identity


def prove_constants() -> None:
    require(IDENTITY["IDENTITY_RECORD_MAGIC"] == 0x31444952, "magic constant")
    require(IDENTITY["IDENTITY_RECORD_HEADER_LEN"] == 48, "header length")
    require(IDENTITY["IDENTITY_RECORD_SIZE"] == FLASH["FLASH_PAGE_SIZE"], "one page record")
    require(IDENTITY["IDENTITY_RECORD_OFF_IDENTITY"] == 48, "identity offset")
    require(IDENTITY["IDENTITY_RECORD_OFF_PADDING"] == 208, "padding offset")
    require(IDENTITY["IDENTITY_RECORD_PADDING_SIZE"] == 48, "padding size")


def prove_record_model() -> None:
    identity = make_identity(17)
    record = make_record(identity)
    require(load_record(record) == (0, identity), "valid record round-trip")
    require(load_record(b"\xff" * 256)[0] == IDENTITY["IDENTITY_ERR_MISSING"], "missing")
    for off in (0, 4, 5, 6, 8, 12, 16, 48 + 128, 208):
        bad = bytearray(record)
        bad[off] ^= 1
        require(load_record(bytes(bad))[0] == IDENTITY["IDENTITY_ERR_INVAL"], f"bad {off}")


def prove_source_shape() -> None:
    save = body("src/identity/identity_save.S", "identity_save")
    ordered(
        save,
        [
            r"\bcall\s+identity_hash",
            r"\.Lis_build_record:",
            r"\bsw\s+t0,\s*IDENTITY_RECORD_OFF_MAGIC\(s1\)",
            r"\.Lis_copy_identity:",
            r"\.Lis_checksum:",
            r"\bcall\s+sha256_init",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_final",
            r"\bcall\s+flash_erase_sector",
            r"\bcall\s+flash_write_page",
            r"\bcall\s+flash_read",
            r"\.Lis_readback_cmp:",
        ],
        "identity_save record/checksum/write/readback order",
    )

    load = body("src/identity/identity_load.S", "identity_load")
    ordered(
        load,
        [
            r"\bcall\s+flash_read",
            r"\.Lil_erased_scan:",
            r"\.Lil_check_header:",
            r"\.Lil_padding_scan:",
            r"\.Lil_checksum:",
            r"\bcall\s+sha256_init",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_final",
            r"\.Lil_checksum_cmp:",
            r"\.Lil_identity_hash:",
            r"\bcall\s+identity_hash",
            r"\.Lil_hash_cmp:",
            r"\.Lil_copy_to_out:",
        ],
        "identity_load validate-before-copy order",
    )


def main() -> int:
    try:
        prove_constants()
        prove_record_model()
        prove_source_shape()
    except ProofError as exc:
        print(f"identity_persistence: FAIL: {exc}", file=sys.stderr)
        return 1
    print("identity_persistence: proved record format and validate-before-copy shape")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
