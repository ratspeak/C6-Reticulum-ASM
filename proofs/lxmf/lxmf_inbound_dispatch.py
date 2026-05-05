#!/usr/bin/env python3
"""Source/contract verifier for LXMF inbound dispatch."""

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


EQU = parse_equ("src/include/config.S", "src/include/lxmf.S", "src/include/transport.S")


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


def message_id(dest: bytes, source: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(dest + source + payload).digest()


def prove_constants() -> None:
    require(EQU["LXMF_DISPATCH_MODE_DIRECT"] == 0, "direct mode")
    require(EQU["LXMF_DISPATCH_MODE_OPPORTUNISTIC"] == 1, "opportunistic mode")
    require(EQU["LXMF_STATUS_DUPLICATE"] == 1, "duplicate status")
    require(EQU["LXMF_ERR_UNKNOWN_SOURCE"] == -7, "unknown source status")
    require(EQU["LXMF_ERR_CAPACITY"] == -8, "capacity status")
    require(EQU["LXMF_ERR_NO_LINK"] == -9, "no-link status")
    require(EQU["LXMF_PACKED_MAX_STAMPED_LEN"] == 527, "inbound packed cap")
    require(EQU["TRANSPORT_PATH_OFF_PUBLIC_KEY"] == 40, "path public key offset")


def prove_vectors() -> None:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    identity = oracle.identity_from_private_parts(xsk, esk)
    dest = bytes(range(16))
    payload = msgpack.packb([1.5, b"Title", b"Body", {}])
    mid = message_id(dest, identity.hash, payload)
    sig = oracle.ed25519_sign(identity.ed25519_seed, dest + identity.hash + payload + mid)
    direct = dest + identity.hash + sig + payload
    opportunistic = direct[EQU["LXMF_HASH_SIZE"]:]
    reconstructed = dest + opportunistic
    require(direct == reconstructed, "opportunistic destination prefix reconstruction")
    require(len(direct) <= EQU["LXMF_PACKED_MAX_STAMPED_LEN"], "direct cap")
    require(
        oracle.ed25519_verify(identity.ed25519_public, sig, dest + identity.hash + payload + mid),
        "source path ed25519 public key verifies message",
    )


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_inbound_dispatch.S", "lxmf_inbound_dispatch")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llid_invalid",
            r"\bli\s+t0,\s*LXMF_DISPATCH_MODE_DIRECT",
            r"\bbeq\s+s3,\s*t0,\s*\.Llid_direct",
            r"\bli\s+t0,\s*LXMF_DISPATCH_MODE_OPPORTUNISTIC",
            r"\bbeq\s+s3,\s*t0,\s*\.Llid_opportunistic",
            r"\bbeqz\s+s4,\s*\.Llid_no_link",
            r"\bbeqz\s+s2,\s*\.Llid_invalid",
            r"\bli\s+t0,\s*LXMF_PACKED_MAX_STAMPED_LEN - LXMF_HASH_SIZE",
            r"\baddi\s+s5,\s*sp,\s*LID_PACKED_OFF",
            r"\bcall\s+\.Llid_copy_bytes",
            r"\baddi\s+s6,\s*s1,\s*LXMF_HASH_SIZE",
            r"\bli\s+t0,\s*LXMF_PACKED_PREFIX_SIZE",
            r"\bbltu\s+s6,\s*t0,\s*\.Llid_short",
            r"\bli\s+t0,\s*LXMF_PACKED_MAX_STAMPED_LEN",
            r"\bcall\s+transport_path_lookup",
            r"\bbeq\s+a0,\s*t0,\s*\.Llid_unknown_source",
            r"\baddi\s+a3,\s*s8,\s*TRANSPORT_PATH_OFF_PUBLIC_KEY \+ 32",
            r"\bcall\s+lxmf_message_parse",
            r"\bbeq\s+a0,\s*t0,\s*\.Llid_capacity",
            r"\bla\s+s9,\s*lxmf_inbound_slot_valid",
            r"\bla\s+a0,\s*lxmf_inbound_message_id",
            r"\bcall\s+\.Llid_memeq",
            r"\bbeqz\s+a0,\s*\.Llid_duplicate",
            r"\bla\s+a1,\s*lxmf_inbound_message_id",
            r"\bla\s+a1,\s*lxmf_inbound_dest_hash",
            r"\bla\s+a1,\s*lxmf_inbound_source_hash",
            r"\bla\s+t1,\s*lxmf_inbound_payload_len",
            r"\bli\s+a0,\s*LXMF_STATUS_DUPLICATE",
            r"\bli\s+a0,\s*LXMF_ERR_UNKNOWN_SOURCE",
            r"\bli\s+a0,\s*LXMF_ERR_CAPACITY",
            r"\bli\s+a0,\s*LXMF_ERR_NO_LINK",
        ],
        "inbound dispatch mode/reconstruct/lookup/parse/store order",
    )
    state = read("src/state/lxmf.S")
    for symbol in (
        "lxmf_inbound_slot_valid",
        "lxmf_inbound_message_id",
        "lxmf_inbound_dest_hash",
        "lxmf_inbound_source_hash",
        "lxmf_inbound_payload_len",
    ):
        require(symbol in state, f"missing state symbol {symbol}")
    require("@ct:          not-required" in read("src/lxmf/lxmf_inbound_dispatch.S"), "ct annotation")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
