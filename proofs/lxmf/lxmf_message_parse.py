#!/usr/bin/env python3
"""Source/contract verifier for LXMF message parsing."""

from __future__ import annotations

import hashlib
import re
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


EQU = parse_equ("src/include/config.S", "src/include/lxmf.S", "src/include/ed25519.S")


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


def no_stamp_payload(raw_payload: bytes) -> bytes:
    unpacked = msgpack.unpackb(raw_payload)
    return msgpack.packb(unpacked[:4]) if len(unpacked) > 4 else raw_payload


def sign(seed: bytes, dest: bytes, source: bytes, raw_payload: bytes) -> bytes:
    payload = no_stamp_payload(raw_payload)
    message_id = hashlib.sha256(dest + source + payload).digest()
    return oracle.ed25519_sign(seed, dest + source + payload + message_id)


def prove_constants() -> None:
    require(EQU["LXMF_HASH_SIZE"] == 16, "hash size")
    require(EQU["LXMF_SIGNATURE_SIZE"] == 64, "signature size")
    require(EQU["LXMF_PACKED_PREFIX_SIZE"] == 96, "packed prefix")
    require(EQU["LXMF_ERR_SHORT"] == -6, "short status")
    require(EQU["LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID"] == 28, "message id offset")
    require(EQU["LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PARSED"] == 60, "payload parsed offset")
    require(EQU["LXMF_MESSAGE_PARSED_T_SIZE"] == 516, "message parsed size")
    require(EQU["ED25519_PUB_BYTES"] == 32, "public key size")


def prove_vectors() -> None:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    identity = oracle.identity_from_private_parts(xsk, esk)
    dest = bytes(range(16))
    base_payload = msgpack.packb([1.5, b"Title", b"Body", {}])
    stamped_payload = bytes([EQU["LXMF_MSGPACK_FIXARRAY5"]]) + base_payload[1:] + b"\xc4\x10" + (b"\x11" * 16)

    for raw_payload in (base_payload, stamped_payload):
        stripped_payload = no_stamp_payload(raw_payload)
        signature = sign(identity.ed25519_seed, dest, identity.hash, raw_payload)
        packed = dest + identity.hash + signature + raw_payload
        require(packed[:16] == dest, "destination prefix")
        require(packed[16:32] == identity.hash, "source prefix")
        require(packed[32:96] == signature, "signature prefix")
        require(packed[96:] == raw_payload, "payload suffix")
        message_id = hashlib.sha256(dest + identity.hash + stripped_payload).digest()
        require(
            oracle.ed25519_verify(
                identity.ed25519_public,
                signature,
                dest + identity.hash + stripped_payload + message_id,
            ),
            "signature verifies over no-stamp payload",
        )


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_message_parse.S", "lxmf_message_parse")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llmr_invalid",
            r"\bbeqz\s+s2,\s*\.Llmr_invalid",
            r"\bbeqz\s+s3,\s*\.Llmr_invalid",
            r"\bli\s+t0,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\bbltu\s+s1,\s*t0,\s*\.Llmr_short",
            r"\bsub\s+s4,\s*s1,\s*t0",
            r"\baddi\s+s5,\s*s2,\s*LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PARSED",
            r"\baddi\s+a0,\s*s0,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\bcall\s+lxmf_payload_parse",
            r"\bsw\s+s0,\s*LXMF_MESSAGE_PARSED_OFF_DEST_HASH_PTR\(s2\)",
            r"\bsw\s+t0,\s*LXMF_MESSAGE_PARSED_OFF_SOURCE_HASH_PTR\(s2\)",
            r"\bsw\s+t0,\s*LXMF_MESSAGE_PARSED_OFF_SIGNATURE_PTR\(s2\)",
            r"\bsw\s+t0,\s*LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PTR\(s2\)",
            r"\blw\s+s6,\s*LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR\(s5\)",
            r"\blw\s+s7,\s*LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN\(s5\)",
            r"\baddi\s+a4,\s*s2,\s*LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID",
            r"\bcall\s+lxmf_message_id",
            r"\baddi\s+a4,\s*s0,\s*LXMF_SIGNING_PREFIX_SIZE",
            r"\bcall\s+lxmf_message_verify",
            r"\bli\s+a0,\s*LXMF_ERR_SHORT",
        ],
        "message parse validation/payload/id/verify order",
    )
    require("@ct:          not-required" in read("src/lxmf/lxmf_message_parse.S"), "ct annotation")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
