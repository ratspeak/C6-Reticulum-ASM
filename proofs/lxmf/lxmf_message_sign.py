#!/usr/bin/env python3
"""Source/contract verifier for LXMF message signing."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests"))

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


EQU = parse_equ("src/include/config.S", "src/include/identity.S", "src/include/lxmf.S")


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


def signing_material(dest: bytes, source: bytes, payload_without_stamp: bytes) -> bytes:
    require(len(dest) == EQU["LXMF_HASH_SIZE"], "dest hash length")
    require(len(source) == EQU["LXMF_HASH_SIZE"], "source hash length")
    require(0 < len(payload_without_stamp) <= EQU["LXMF_PAYLOAD_MAX_LEN"], "payload length")
    message_id = hashlib.sha256(dest + source + payload_without_stamp).digest()
    return dest + source + payload_without_stamp + message_id


def prove_constants() -> None:
    require(EQU["LXMF_HASH_SIZE"] == 16, "hash size")
    require(EQU["LXMF_MESSAGE_ID_SIZE"] == 32, "message id size")
    require(EQU["LXMF_SIGNATURE_SIZE"] == 64, "signature size")
    require(EQU["LXMF_SIGNING_MAX_LEN"] == 461, "signing cap")
    require(EQU["IDENTITY_OFF_ED25519_SK"] == 32, "identity ed25519 seed offset")
    require(EQU["IDENTITY_OFF_HASH"] == 128, "identity hash offset")


def prove_vectors() -> None:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    identity = oracle.identity_from_private_parts(xsk, esk)
    dest = bytes(range(16))
    payload = bytes.fromhex("94cb3ff8000000000000c4055469746c65c404426f647980")
    material = signing_material(dest, identity.hash, payload)
    sig = oracle.ed25519_sign(identity.ed25519_seed, material)
    require(len(material) == 64 + len(payload), "signed material length")
    require(len(sig) == EQU["LXMF_SIGNATURE_SIZE"], "signature length")
    require(
        oracle.ed25519_verify(identity.ed25519_public, sig, material),
        "signature verifies against identity public key",
    )


def prove_source_shape() -> None:
    src = body("src/lxmf/lxmf_message_sign.S", "lxmf_message_sign")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llms_invalid",
            r"\bbeqz\s+s1,\s*\.Llms_invalid",
            r"\bbeqz\s+s2,\s*\.Llms_invalid",
            r"\bbeqz\s+s3,\s*\.Llms_invalid",
            r"\bbeqz\s+s4,\s*\.Llms_invalid",
            r"\bli\s+t0,\s*LXMF_PAYLOAD_MAX_LEN",
            r"\bcall\s+identity_load",
            r"\baddi\s+t0,\s*s5,\s*IDENTITY_OFF_HASH",
            r"\bli\s+t2,\s*IDENTITY_HASH_SIZE",
            r"\bxor\s+t6,\s*t4,\s*t5",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+\.Llms_copy_bytes",
            r"\baddi\s+a1,\s*s6,\s*16",
            r"\bli\s+a2,\s*LXMF_HASH_SIZE",
            r"\bcall\s+\.Llms_copy_bytes",
            r"\baddi\s+a1,\s*s6,\s*32",
            r"\bcall\s+\.Llms_copy_bytes",
            r"\bcall\s+lxmf_message_id",
            r"\bli\s+s7,\s*64",
            r"\baddi\s+a3,\s*s5,\s*IDENTITY_OFF_ED25519_SK",
            r"\bcall\s+ed25519_sign",
        ],
        "message signing validation/material/sign order",
    )
    require("LXMF_ERR_MISSING" in src and "LXMF_ERR_IO" in src, "identity error mapping")
    require("@ct:          required" in read("src/lxmf/lxmf_message_sign.S"), "ct annotation")


def main() -> None:
    prove_constants()
    prove_vectors()
    prove_source_shape()


if __name__ == "__main__":
    main()
