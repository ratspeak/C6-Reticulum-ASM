#!/usr/bin/env python3
"""Source/contract verifier for milestone-6 link_handshake_accept."""

from __future__ import annotations

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


def link_id(dest: bytes, xpub: bytes, epub: bytes) -> bytes:
    require(len(dest) == 16, "dest len")
    require(len(xpub) == 32, "xpub len")
    require(len(epub) == 32, "epub len")
    hashable = bytes([LINK["LINK_REQUEST_HEADER_FLAGS"]]) + dest + b"\x00" + xpub + epub
    return hashlib.sha256(hashable).digest()[:16]


def accept_status(
    valid: bool,
    raw_len: int,
    mtu: int,
    mode: int,
    duplicate: bool,
) -> int:
    if not valid:
        return LINK["LINK_ERR_INVAL"]
    if raw_len != LINK["LINK_REQUEST_RAW_LEN"]:
        return LINK["LINK_ERR_INVAL"]
    if mtu != LINK["LINK_DEFAULT_MTU"]:
        return LINK["LINK_ERR_INVAL"]
    if mode != LINK["LINK_MODE_AES256_CBC"]:
        return LINK["LINK_ERR_INVAL"]
    return LINK["LINK_STATUS_DUPLICATE"] if duplicate else LINK["LINK_OK"]


def prove_constants() -> None:
    require(LINK["LINK_STATUS_DUPLICATE"] == 1, "duplicate status")
    require(LINK["LINK_STATUS_ESTABLISHED"] == 2, "established status")
    require(LINK["LINK_REQUEST_ID_HASHABLE_LEN"] == 82, "link-id hashable len")
    require(LINK["LINK_ID_SIZE"] == 16, "link id size")
    require(LINK["LINK_ENTRY_OFF_LINK_ID"] == 216, "link id offset")
    require(LINK["LINK_ENTRY_OFF_KEY_MATERIAL"] == 232, "key material offset")
    require(LINK["LINK_ENTRY_SIZE"] == 296, "entry size")


def prove_status_model() -> None:
    require(
        accept_status(True, LINK["LINK_REQUEST_RAW_LEN"], LINK["LINK_DEFAULT_MTU"],
                      LINK["LINK_MODE_AES256_CBC"], False) == LINK["LINK_OK"],
        "new accept status",
    )
    require(
        accept_status(True, LINK["LINK_REQUEST_RAW_LEN"], LINK["LINK_DEFAULT_MTU"],
                      LINK["LINK_MODE_AES256_CBC"], True)
        == LINK["LINK_STATUS_DUPLICATE"],
        "duplicate status",
    )
    for args in (
        (False, LINK["LINK_REQUEST_RAW_LEN"], LINK["LINK_DEFAULT_MTU"],
         LINK["LINK_MODE_AES256_CBC"], False),
        (True, 0, LINK["LINK_DEFAULT_MTU"], LINK["LINK_MODE_AES256_CBC"], False),
        (True, LINK["LINK_REQUEST_RAW_LEN"], 501, LINK["LINK_MODE_AES256_CBC"], False),
        (True, LINK["LINK_REQUEST_RAW_LEN"], LINK["LINK_DEFAULT_MTU"], 0, False),
    ):
        require(accept_status(*args) == LINK["LINK_ERR_INVAL"],
                f"invalid accepted {args}")


def prove_link_id_vector() -> None:
    dest = bytes(range(16))
    xpub = bytes(range(0x20, 0x40))
    epub = bytes(range(0x80, 0xA0))
    require(link_id(dest, xpub, epub).hex() == "8dd0a887601c3fa3757b7ff0fd2c39d1",
            "link id vector")


def prove_source_shape() -> None:
    src = body("src/link/link_handshake_accept.S", "link_handshake_accept")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llha_invalid",
            r"\blw\s+t0,\s*LINK_REQUEST_OFF_RAW_LEN\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llha_invalid",
            r"\blw\s+t0,\s*LINK_REQUEST_OFF_MTU\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llha_invalid",
            r"\blw\s+t0,\s*LINK_REQUEST_OFF_MODE\(s0\)",
            r"\bbne\s+t0,\s*t1,\s*\.Llha_invalid",
            r"\bcall\s+clock_now_ms",
            r"\bla\s+s8,\s*link_table",
            r"\.Llha_scan:",
            r"\bcall\s+\.Llha_memeq",
            r"\bli\s+t1,\s*LINK_STATUS_ESTABLISHED",
            r"\bcall\s+\.Llha_memeq",
            r"\bli\s+a0,\s*LINK_STATUS_DUPLICATE",
            r"\.Llha_have_entry:",
            r"\bcall\s+x25519_keypair",
            r"\bcall\s+x25519_scalar_mult",
            r"\bli\s+t1,\s*LINK_REQUEST_HEADER_FLAGS",
            r"\bcall\s+sha256_init",
            r"\bcall\s+sha256_update",
            r"\bcall\s+sha256_final",
            r"\bcall\s+link_derive_keys",
            r"\bli\s+t0,\s*LINK_STATUS_ESTABLISHED",
            r"\bsb\s+t0,\s*LINK_ENTRY_OFF_STATUS\(s3\)",
            r"\bcall\s+\.Llha_zero_bytes",
            r"\bsb\s+t0,\s*LINK_ENTRY_OFF_VALID\(s3\)",
        ],
        "link_handshake_accept validate/duplicate/derive/store order",
    )
    first_keygen = src.index("call    x25519_keypair")
    require("call    link_derive_keys" not in src[:first_keygen],
            "derive before key generation")
    require(src.count("call    x25519_keypair") == 1, "keypair count")
    require(src.count("call    x25519_scalar_mult") == 1, "scalar mult count")
    require(src.count("call    link_derive_keys") == 1, "derive count")


def main() -> None:
    prove_constants()
    prove_status_model()
    prove_link_id_vector()
    prove_source_shape()


if __name__ == "__main__":
    main()
