"""proofs/crypto/aes/_aes_oracle.py

Python reference for AES-256 — mirror of AES256.cry, used as the oracle
for the per-function angr verifiers in this directory. Implements every
internal step (sbox, subbytes, shiftrows, mixcolumns, addroundkey,
subword, key-expand, encrypt-block, decrypt-block) plus CBC mode, all
from FIPS 197 first principles.

This is the ONLY place where AES algorithm state lives in Python. Each
per-function .py verifier imports from here.
"""
from __future__ import annotations

import struct

# ---- FIPS 197 §5.1.1 S-box and Inverse S-box -----------------------------

SBOX = bytes((
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
))

INV_SBOX = bytes((
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
))

# Round constants per FIPS 197 §5.2 (rcon[1..10] for AES-256).
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


# ---- GF(2^8) -------------------------------------------------------------

def xtime(b: int) -> int:
    return ((b << 1) ^ 0x1b) & 0xff if b & 0x80 else (b << 1) & 0xff


def gf_mul(b: int, n: int) -> int:
    """Multiply b by the constant n in GF(2^8) (n in {1,2,4,8,9,11,13,14})."""
    if n == 1:
        return b
    if n == 2:
        return xtime(b)
    if n == 4:
        return xtime(xtime(b))
    if n == 8:
        return xtime(xtime(xtime(b)))
    if n == 9:
        return b ^ gf_mul(b, 8)
    if n == 11:
        return b ^ gf_mul(b, 2) ^ gf_mul(b, 8)
    if n == 13:
        return b ^ gf_mul(b, 4) ^ gf_mul(b, 8)
    if n == 14:
        return gf_mul(b, 2) ^ gf_mul(b, 4) ^ gf_mul(b, 8)
    raise ValueError(n)


# ---- per-byte / per-word / per-state primitives --------------------------

def sub_byte(b: int) -> int:
    return SBOX[b]


def inv_sub_byte(b: int) -> int:
    return INV_SBOX[b]


def sub_word(word: int) -> int:
    """Apply S-box to each of 4 little-endian bytes of a 32-bit word."""
    bs = word.to_bytes(4, "little")
    return int.from_bytes(bytes(SBOX[b] for b in bs), "little")


def rot_word(word: int) -> int:
    """Cyclically rotate the 4 little-endian bytes left by 1."""
    bs = word.to_bytes(4, "little")
    return int.from_bytes(bytes((bs[1], bs[2], bs[3], bs[0])), "little")


def sub_bytes(state: bytes) -> bytes:
    return bytes(SBOX[b] for b in state)


def inv_sub_bytes(state: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in state)


def add_round_key(state: bytes, rk: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(state, rk))


def shift_rows(state: bytes) -> bytes:
    """Apply ShiftRows to a 16-byte state (column-major).
    Row r is rotated left by r positions."""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = state[((c + r) % 4) * 4 + r]
    return bytes(out)


def inv_shift_rows(state: bytes) -> bytes:
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = state[((c + 4 - r) % 4) * 4 + r]
    return bytes(out)


def mix_columns(state: bytes) -> bytes:
    out = bytearray(16)
    for c in range(4):
        c0, c1, c2, c3 = state[c*4:c*4+4]
        out[c*4 + 0] = gf_mul(c0, 2) ^ (c1 ^ gf_mul(c1, 2)) ^ c2 ^ c3
        out[c*4 + 1] = c0 ^ gf_mul(c1, 2) ^ (c2 ^ gf_mul(c2, 2)) ^ c3
        out[c*4 + 2] = c0 ^ c1 ^ gf_mul(c2, 2) ^ (c3 ^ gf_mul(c3, 2))
        out[c*4 + 3] = (c0 ^ gf_mul(c0, 2)) ^ c1 ^ c2 ^ gf_mul(c3, 2)
    return bytes(out)


def inv_mix_columns(state: bytes) -> bytes:
    out = bytearray(16)
    for c in range(4):
        c0, c1, c2, c3 = state[c*4:c*4+4]
        out[c*4 + 0] = gf_mul(c0, 14) ^ gf_mul(c1, 11) ^ gf_mul(c2, 13) ^ gf_mul(c3, 9)
        out[c*4 + 1] = gf_mul(c0, 9)  ^ gf_mul(c1, 14) ^ gf_mul(c2, 11) ^ gf_mul(c3, 13)
        out[c*4 + 2] = gf_mul(c0, 13) ^ gf_mul(c1, 9)  ^ gf_mul(c2, 14) ^ gf_mul(c3, 11)
        out[c*4 + 3] = gf_mul(c0, 11) ^ gf_mul(c1, 13) ^ gf_mul(c2, 9)  ^ gf_mul(c3, 14)
    return bytes(out)


# ---- AES-256 key schedule -----------------------------------------------

def expand_key(key: bytes) -> bytes:
    """AES-256 key expansion: 32-byte key -> 240-byte schedule (60 words)."""
    assert len(key) == 32
    w = list(struct.unpack("<8I", key))   # little-endian per the asm convention
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[(i // 8) - 1]
        elif i % 8 == 4:
            temp = sub_word(temp)
        w.append((w[i - 8] ^ temp) & 0xFFFFFFFF)
    return b"".join(struct.pack("<I", x) for x in w)


# ---- block encrypt / decrypt --------------------------------------------

def encrypt_block(round_keys: bytes, pt: bytes) -> bytes:
    """AES-256 single-block encrypt. round_keys = 240 bytes from expand_key()."""
    assert len(round_keys) == 240 and len(pt) == 16
    state = add_round_key(pt, round_keys[0:16])
    for r in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r * 16:(r + 1) * 16])
    state = sub_bytes(state)
    state = shift_rows(state)
    return add_round_key(state, round_keys[14 * 16:15 * 16])


def decrypt_block(round_keys: bytes, ct: bytes) -> bytes:
    """AES-256 single-block decrypt (matches the asm's per-round structure)."""
    assert len(round_keys) == 240 and len(ct) == 16
    state = add_round_key(ct, round_keys[14 * 16:15 * 16])
    for r in range(13, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r * 16:(r + 1) * 16])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    return add_round_key(state, round_keys[0:16])


def cbc_encrypt(round_keys: bytes, iv: bytes, pt: bytes) -> bytes:
    assert len(iv) == 16 and len(pt) % 16 == 0
    out = bytearray()
    prev = iv
    for off in range(0, len(pt), 16):
        block = bytes(a ^ b for a, b in zip(prev, pt[off:off + 16]))
        prev = encrypt_block(round_keys, block)
        out += prev
    return bytes(out)


def cbc_decrypt(round_keys: bytes, iv: bytes, ct: bytes) -> bytes:
    assert len(iv) == 16 and len(ct) % 16 == 0
    out = bytearray()
    prev = iv
    for off in range(0, len(ct), 16):
        block = ct[off:off + 16]
        decrypted = decrypt_block(round_keys, block)
        out += bytes(a ^ b for a, b in zip(prev, decrypted))
        prev = block
    return bytes(out)


# ---- self-test ----------------------------------------------------------

if __name__ == "__main__":
    # FIPS 197 §C.3 — AES-256 single block.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    rk = expand_key(key)
    actual_ct = encrypt_block(rk, pt)
    assert actual_ct == expected_ct, f"FIPS C.3 enc mismatch: {actual_ct.hex()}"
    actual_pt = decrypt_block(rk, expected_ct)
    assert actual_pt == pt, f"FIPS C.3 dec mismatch: {actual_pt.hex()}"

    # NIST SP 800-38A §F.2.5 — AES-256-CBC.
    cbc_key = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                            "1f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cbc_pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                           "ae2d8a571e03ac9c9eb76fac45af8e51"
                           "30c81c46a35ce411e5fbc1191a0a52ef"
                           "f69f2445df4f9b17ad2b417be66c3710")
    cbc_ct = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                           "9cfc4e967edb808d679f777bc6702c7d"
                           "39f23369a9d9bacfa530e26304231461"
                           "b2eb05e2c39be9fcda6c19078c6a9d1b")
    cbc_rk = expand_key(cbc_key)
    actual_cbc_ct = cbc_encrypt(cbc_rk, iv, cbc_pt)
    assert actual_cbc_ct == cbc_ct, f"NIST F.2.5 enc mismatch: {actual_cbc_ct.hex()}"
    actual_cbc_pt = cbc_decrypt(cbc_rk, iv, cbc_ct)
    assert actual_cbc_pt == cbc_pt, f"NIST F.2.6 dec mismatch: {actual_cbc_pt.hex()}"

    print("AES oracle self-test PASS")
