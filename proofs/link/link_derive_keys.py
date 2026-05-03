#!/usr/bin/env python3
"""Source/contract verifier for milestone-6 link_derive_keys."""

from __future__ import annotations

import hashlib
import hmac
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
    "src/include/hkdf.S",
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


def hkdf_sha256(shared_secret: bytes, salt: bytes, length: int = 64) -> bytes:
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    block = b""
    out = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def prove_constants() -> None:
    require(LINK["LINK_SHARED_SECRET_SIZE"] == 32, "X25519 shared secret size")
    require(LINK["LINK_PRK_SIZE"] == 32, "HKDF PRK size")
    require(LINK["HKDF_HASH_LEN"] == 32, "HKDF hash len")
    require(LINK["LINK_KEY_MATERIAL_SIZE"] == 64, "AES-256-CBC token material")
    require(LINK["LINK_ERR_INVAL"] < 0, "invalid status negative")
    require(LINK["LINK_OK"] == 0, "success status")


def prove_reference_vector() -> None:
    shared = bytes((0x10 + i * 7) & 0xFF for i in range(32))
    salt = bytes((0x80 + i * 11) & 0xFF for i in range(16))
    out = hkdf_sha256(shared, salt)
    require(len(out) == LINK["LINK_KEY_MATERIAL_SIZE"], "HKDF output length")
    require(out[:8].hex() == "67e40ce69abbb7eb", "HKDF vector prefix")
    require(out[-8:].hex() == "dfb851a52035ca71", "HKDF vector suffix")


def prove_source_shape() -> None:
    src = body("src/link/link_derive_keys.S", "link_derive_keys")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Lldk_fail",
            r"\bbeqz\s+s1,\s*\.Lldk_fail",
            r"\bbeqz\s+s2,\s*\.Lldk_fail",
            r"\bbeqz\s+s3,\s*\.Lldk_fail",
            r"\bmv\s+a0,\s*s1",
            r"\bmv\s+a1,\s*s2",
            r"\bmv\s+a2,\s*s0",
            r"\bli\s+a3,\s*LINK_SHARED_SECRET_SIZE",
            r"\baddi\s+a4,\s*sp,\s*LDK_PRK_OFF",
            r"\bcall\s+hkdf_extract",
            r"\baddi\s+a0,\s*sp,\s*LDK_PRK_OFF",
            r"\bli\s+a1,\s*LINK_PRK_SIZE",
            r"\bmv\s+a2,\s*zero",
            r"\bli\s+a3,\s*0",
            r"\bmv\s+a4,\s*s3",
            r"\bli\s+a5,\s*LINK_KEY_MATERIAL_SIZE",
            r"\bcall\s+hkdf_expand",
            r"\bli\s+a0,\s*LINK_OK",
        ],
        "link_derive_keys extract/expand order",
    )
    first_call = src.index("call    hkdf_extract")
    before_calls = src[:first_call]
    require(
        before_calls.count(".Lldk_fail") >= 4,
        "invalid checks are not before HKDF calls",
    )
    require(src.count("call    hkdf_extract") == 1, "extract call count")
    require(src.count("call    hkdf_expand") == 1, "expand call count")


def main() -> None:
    prove_constants()
    prove_reference_vector()
    prove_source_shape()


if __name__ == "__main__":
    main()
