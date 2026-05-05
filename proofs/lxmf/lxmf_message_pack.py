#!/usr/bin/env python3
"""Source/contract verifier for LXMF message packing."""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import RNS.vendor.umsgpack as msgpack  # noqa: E402
from harness import oracle  # noqa: E402


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


def payload(timestamp: float, title: bytes, content: bytes, fields: bytes = b"\x80") -> bytes:
    require(len(title) <= EQU["LXMF_PAYLOAD_MAX_TITLE"], "title cap")
    require(len(content) <= EQU["LXMF_PAYLOAD_MAX_CONTENT"], "content cap")
    require(len(fields) <= EQU["LXMF_PAYLOAD_MAX_FIELDS"], "fields cap")
    ts = struct.pack(">d", timestamp)
    out = bytearray([EQU["LXMF_MSGPACK_FIXARRAY4"], EQU["LXMF_MSGPACK_FLOAT64"]])
    out.extend(ts)
    out.extend((EQU["LXMF_MSGPACK_BIN8"], len(title)))
    out.extend(title)
    out.extend((EQU["LXMF_MSGPACK_BIN8"], len(content)))
    out.extend(content)
    out.extend(fields)
    return bytes(out)


def packed_message(
    dest: bytes,
    source: bytes,
    seed: bytes,
    payload_without_stamp: bytes,
) -> bytes:
    require(len(dest) == EQU["LXMF_HASH_SIZE"], "dest hash length")
    require(len(source) == EQU["LXMF_HASH_SIZE"], "source hash length")
    message_id = hashlib.sha256(dest + source + payload_without_stamp).digest()
    signature = oracle.ed25519_sign(seed, dest + source + payload_without_stamp + message_id)
    return dest + source + signature + payload_without_stamp


def prove_constants() -> None:
    require(EQU["LXMF_HASH_SIZE"] == 16, "hash size")
    require(EQU["LXMF_SIGNATURE_SIZE"] == 64, "signature size")
    require(EQU["LXMF_PAYLOAD_MAX_LEN"] == 397, "payload cap")
    require(EQU["LXMF_PACKED_PREFIX_SIZE"] == 96, "packed prefix")
    require(EQU["LXMF_PACKED_MAX_LEN"] == 493, "packed cap")


def prove_vectors() -> None:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    identity = oracle.identity_from_private_parts(xsk, esk)
    dest = bytes(range(16))
    payload_bytes = payload(1.5, b"Title", b"Body")
    upstream_payload = msgpack.packb([1.5, b"Title", b"Body", {}])
    require(payload_bytes == upstream_payload, "payload vector matches upstream MessagePack")
    packed = packed_message(dest, identity.hash, identity.ed25519_seed, payload_bytes)
    require(len(packed) == EQU["LXMF_PACKED_PREFIX_SIZE"] + len(payload_bytes), "packed length")
    require(packed[:16] == dest, "destination prefix")
    require(packed[16:32] == identity.hash, "source prefix")
    require(packed[96:] == payload_bytes, "payload suffix")
    message_id = hashlib.sha256(dest + identity.hash + payload_bytes).digest()
    require(
        oracle.ed25519_verify(
            identity.ed25519_public,
            packed[32:96],
            dest + identity.hash + payload_bytes + message_id,
        ),
        "packed signature verifies",
    )


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_message_pack.S", "lxmf_message_pack")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llmp_invalid",
            r"\bbeqz\s+s1,\s*\.Llmp_invalid",
            r"\bbeqz\s+s2,\s*\.Llmp_invalid",
            r"\bbeqz\s+s3,\s*\.Llmp_invalid",
            r"\bli\s+t0,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\bbltu\s+s4,\s*t0,\s*\.Llmp_overflow",
            r"\baddi\s+a1,\s*s3,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\bsub\s+a2,\s*s4,\s*t0",
            r"\bcall\s+lxmf_payload_build",
            r"\bblt\s+a0,\s*zero,\s*\.Llmp_done",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+\.Llmp_copy_bytes",
            r"\baddi\s+a1,\s*s3,\s*LXMF_HASH_SIZE",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+\.Llmp_copy_bytes",
            r"\baddi\s+a2,\s*s3,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\baddi\s+a4,\s*s3,\s*LXMF_SIGNING_PREFIX_SIZE",
            r"\bcall\s+lxmf_message_sign",
            r"\bli\s+a0,\s*LXMF_PACKED_PREFIX_SIZE",
        ],
        "message pack validation/build/copy/sign order",
    )
    require("@ct:          required" in read("src/lxmf/lxmf_message_pack.S"), "ct annotation")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
