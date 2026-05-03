#!/usr/bin/env python3
"""Source/contract verifier for milestone-6 link session tokens."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    "src/include/link.S",
    "src/include/aes.S",
    "src/include/hmac.S",
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


def token_encrypt(key_material: bytes, iv: bytes, plaintext: bytes) -> bytes:
    require(len(key_material) == 64, "key material length")
    require(len(iv) == 16, "iv length")
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key_material[32:]), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    signed = iv + ciphertext
    tag = hmac.new(key_material[:32], signed, hashlib.sha256).digest()
    return signed + tag


def prove_constants() -> None:
    require(LINK["LINK_SESSION_IV_SIZE"] == 16, "session IV size")
    require(LINK["LINK_SESSION_HMAC_SIZE"] == 32, "session HMAC size")
    require(LINK["LINK_SESSION_TOKEN_OVERHEAD"] == 48, "token overhead")
    require(LINK["LINK_SESSION_PLAINTEXT_MAX"] == 431, "Reticulum link plaintext MDU")
    require(LINK["LINK_SESSION_PADDED_MAX"] == 432, "max padded plaintext")
    require(LINK["LINK_SESSION_TOKEN_MAX"] == 480, "max token")
    require(LINK["LINK_KEY_MATERIAL_SIZE"] == 64, "AES-256-CBC token key material")

    state = read("src/state/link.S")
    require("link_session_scratch:" in state, "session scratch symbol")
    require(".skip LINK_SESSION_PADDED_MAX" in state, "session scratch size")


def prove_token_vector() -> None:
    key_material = bytes((0x21 + i * 11) & 0xFF for i in range(64))
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    token = token_encrypt(key_material, iv, b"hello link session")
    require(
        token.hex()
        == "00112233445566778899aabbccddeeff"
           "fb9f123ac4448ef9d6967ea04cf1df86"
           "5d51995a8320988719db956b48c46fac"
           "3ed738079d70b47bf611997a765f3a36"
           "98198749f35c9dd6920c5039471944c4",
        "AES-256-CBC token vector",
    )


def prove_encrypt_source_shape() -> None:
    src = body("src/link/link_session_encrypt.S", "link_session_encrypt")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llse_invalid",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_VALID\(s0\)",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_STATUS\(s0\)",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_MODE\(s0\)",
            r"\bli\s+t0,\s*LINK_SESSION_PLAINTEXT_MAX",
            r"\bbltu\s+t0,\s*s2,\s*\.Llse_overflow",
            r"\bcall\s+\.Llse_copy_bytes",
            r"\bcall\s+\.Llse_fill_bytes",
            r"\bcall\s+rng_bytes",
            r"\bcall\s+aes256_key_expand",
            r"\bcall\s+aes256_cbc_encrypt",
            r"\bcall\s+hmac_sha256",
        ],
        "encrypt validate/pad/encrypt/auth order",
    )
    require(src.count("call    rng_bytes") == 1, "encrypt rng call count")
    require(src.count("call    aes256_cbc_encrypt") == 1, "encrypt CBC call count")
    require(src.count("call    hmac_sha256") == 1, "encrypt HMAC call count")


def prove_decrypt_source_shape() -> None:
    src = body("src/link/link_session_decrypt.S", "link_session_decrypt")
    ordered(
        src,
        [
            r"\bbeqz\s+s0,\s*\.Llsd_invalid",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_VALID\(s0\)",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_STATUS\(s0\)",
            r"\blbu\s+t0,\s*LINK_ENTRY_OFF_MODE\(s0\)",
            r"\bli\s+t0,\s*LINK_SESSION_TOKEN_OVERHEAD \+ 16",
            r"\bcall\s+hmac_sha256",
            r"\bcall\s+\.Llsd_memeq",
            r"\bbeqz\s+a0,\s*\.Llsd_invalid",
            r"\bcall\s+aes256_key_expand",
            r"\bcall\s+aes256_cbc_decrypt",
            r"\blbu\s+s8,\s*0\(t0\)",
            r"\bbeqz\s+s8,\s*\.Llsd_invalid",
            r"\bcall\s+\.Llsd_check_pad",
            r"\bbltu\s+s4,\s*s9,\s*\.Llsd_overflow",
            r"\bcall\s+\.Llsd_copy_bytes",
        ],
        "decrypt authenticate/decrypt/unpad/release order",
    )
    require(src.index("call    hmac_sha256") < src.index("call    aes256_cbc_decrypt"),
            "decrypts before authenticating")
    require(src.index("call    .Llsd_check_pad") < src.index("call    .Llsd_copy_bytes"),
            "copies plaintext before padding check")
    require(src.count("call    hmac_sha256") == 1, "decrypt HMAC call count")
    require(src.count("call    aes256_cbc_decrypt") == 1, "decrypt CBC call count")


def main() -> None:
    prove_constants()
    prove_token_vector()
    prove_encrypt_source_shape()
    prove_decrypt_source_shape()


if __name__ == "__main__":
    main()
