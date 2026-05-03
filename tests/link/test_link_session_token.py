"""Direct QEMU tests for milestone-6 link session tokens."""

from __future__ import annotations

import dataclasses
import hmac
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/link/link_session_encrypt.S",
    "src/link/link_session_decrypt.S",
    "src/crypto/aes/aes256_key_expand.S",
    "src/crypto/aes/aes256_cbc_encrypt.S",
    "src/crypto/aes/aes256_cbc_decrypt.S",
    "src/crypto/aes/aes256_encrypt_block.S",
    "src/crypto/aes/aes256_decrypt_block.S",
    "src/crypto/aes/aes_addroundkey.S",
    "src/crypto/aes/aes_subbytes.S",
    "src/crypto/aes/aes_invsubbytes.S",
    "src/crypto/aes/aes_shiftrows.S",
    "src/crypto/aes/aes_invshiftrows.S",
    "src/crypto/aes/aes_mixcolumns.S",
    "src/crypto/aes/aes_invmixcolumns.S",
    "src/crypto/aes/aes_sbox.S",
    "src/crypto/aes/aes_invsbox.S",
    "src/crypto/aes/aes_subword.S",
    "src/crypto/rng/rng_init.S",
    "src/crypto/rng/rng_entropy.S",
    "src/crypto/rng/rng_bytes.S",
    "src/crypto/rng/hmac_drbg_update.S",
    "src/crypto/hmac/hmac_sha256.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/link.S",
    "src/state/aes.S",
    "src/state/rng.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
)

LINK_ENTRY_SIZE = 296
LINK_ENTRY_OFF_KEY_MATERIAL = 232
LINK_SESSION_PLAINTEXT_MAX = 431
LINK_SESSION_TOKEN_MAX = 480
LINK_SESSION_TOKEN_OVERHEAD = 48

KEY_MATERIAL = bytes((0x21 + i * 11) & 0xFF for i in range(64))
FIXED_IV = bytes.fromhex("00112233445566778899aabbccddeeff")


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _token_for(plaintext: bytes, *, iv: bytes = FIXED_IV) -> bytes:
    signing_key = KEY_MATERIAL[:32]
    encryption_key = KEY_MATERIAL[32:]
    ciphertext = _aes_cbc_encrypt(encryption_key, iv, _pkcs7_pad(plaintext))
    signed = iv + ciphertext
    return signed + hmac.new(signing_key, signed, hashlib.sha256).digest()


def _token_with_bad_padding() -> bytes:
    signing_key = KEY_MATERIAL[:32]
    encryption_key = KEY_MATERIAL[32:]
    ciphertext = _aes_cbc_encrypt(encryption_key, FIXED_IV, (b"A" * 15) + b"\x00")
    signed = FIXED_IV + ciphertext
    return signed + hmac.new(signing_key, signed, hashlib.sha256).digest()


def _expected_token_with_iv(plaintext: bytes, token_iv: bytes) -> bytes:
    return _token_for(plaintext, iv=token_iv)


@dataclasses.dataclass(frozen=True)
class EncryptCase:
    name: str
    plaintext: bytes
    cap: int
    expect_ret: int | None = None
    valid: int = 1
    status: int = 2


@dataclasses.dataclass(frozen=True)
class DecryptCase:
    name: str
    token: bytes
    cap: int
    expect_ret: int
    expect_plaintext: bytes = b""
    valid: int = 1
    status: int = 2


ENCRYPT_CASES = (
    EncryptCase("short", b"hello link session", LINK_SESSION_TOKEN_MAX),
    EncryptCase("empty", b"", LINK_SESSION_TOKEN_MAX),
    EncryptCase("cap-overflow", b"abc", LINK_SESSION_TOKEN_OVERHEAD + 15, -2),
    EncryptCase("plaintext-overflow", b"B" * (LINK_SESSION_PLAINTEXT_MAX + 1), LINK_SESSION_TOKEN_MAX, -2),
    EncryptCase("invalid-entry", b"abc", LINK_SESSION_TOKEN_MAX, -1, valid=0),
)

VALID_DECRYPT_1 = b"hello link session"
VALID_DECRYPT_2 = b""
TAMPER_IV = bytearray(_token_for(VALID_DECRYPT_1))
TAMPER_IV[0] ^= 0x01
TAMPER_CT = bytearray(_token_for(VALID_DECRYPT_1))
TAMPER_CT[20] ^= 0x01
TAMPER_TAG = bytearray(_token_for(VALID_DECRYPT_1))
TAMPER_TAG[-1] ^= 0x01

DECRYPT_CASES = (
    DecryptCase("short", _token_for(VALID_DECRYPT_1), LINK_SESSION_PLAINTEXT_MAX, len(VALID_DECRYPT_1), VALID_DECRYPT_1),
    DecryptCase("empty", _token_for(VALID_DECRYPT_2), LINK_SESSION_PLAINTEXT_MAX, 0, VALID_DECRYPT_2),
    DecryptCase("tampered-iv", bytes(TAMPER_IV), LINK_SESSION_PLAINTEXT_MAX, -1),
    DecryptCase("tampered-ciphertext", bytes(TAMPER_CT), LINK_SESSION_PLAINTEXT_MAX, -1),
    DecryptCase("tampered-tag", bytes(TAMPER_TAG), LINK_SESSION_PLAINTEXT_MAX, -1),
    DecryptCase("bad-padding", _token_with_bad_padding(), LINK_SESSION_PLAINTEXT_MAX, -1),
    DecryptCase("cap-overflow", _token_for(VALID_DECRYPT_1), len(VALID_DECRYPT_1) - 1, -2),
    DecryptCase("short-token", _token_for(VALID_DECRYPT_1)[:63], LINK_SESSION_PLAINTEXT_MAX, -1),
    DecryptCase("invalid-entry", _token_for(VALID_DECRYPT_1), LINK_SESSION_PLAINTEXT_MAX, -1, valid=0),
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} not on PATH")
    return path


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"{' '.join(cmd)} failed with exit {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )


def _byte_list(data: bytes) -> str:
    if not data:
        return "0x00"
    return ", ".join(f"0x{b:02x}" for b in data)


def _entry_bytes(valid: int, status: int) -> bytes:
    prefix = bytes([valid, status, 1, 0])
    return prefix + bytes(LINK_ENTRY_OFF_KEY_MATERIAL - len(prefix)) + KEY_MATERIAL


def _emit_helpers() -> str:
    return """
.Lemit_hex32:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        mv      t2, a0
        li      t3, 28
1:      srl     t4, t2, t3
        andi    a0, t4, 15
        call    .Lnibble_to_ascii
        call    .Lputc
        addi    t3, t3, -4
        bgez    t3, 1b
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lemit_bytes:
        addi    sp, sp, -16
        sw      s0, 0(sp)
        sw      s1, 4(sp)
        sw      ra, 12(sp)
        mv      s0, a0
        mv      s1, a1
2:      beqz    s1, 3f
        lbu     t2, 0(s0)
        srli    a0, t2, 4
        call    .Lnibble_to_ascii
        call    .Lputc
        lbu     t2, 0(s0)
        andi    a0, t2, 15
        call    .Lnibble_to_ascii
        call    .Lputc
        addi    s0, s0, 1
        addi    s1, s1, -1
        j       2b
3:      lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 4f
        addi    a0, a0, 87
        ret
4:      addi    a0, a0, 48
        ret

.Lputc:
        li      t0, 0x10000000
7:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 7b
        sb      a0, 0(t0)
        ret
"""


def _harness_asm(
    *,
    func: str,
    input_data: bytes,
    input_len: int,
    cap: int,
    valid: int,
    status: int,
) -> str:
    input_arg = "plaintext" if func == "link_session_encrypt" else "token"
    output_label = "token_out" if func == "link_session_encrypt" else "plaintext_out"
    return f"""
        .section .text._reset, "ax", @progbits
        .global _reset
        .type   _reset, @function
_reset:
        la      sp, __stack_top

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

        call    rng_init
        la      a0, entry
        la      a1, {input_arg}
        li      a2, {input_len}
        la      a3, {output_label}
        li      a4, {cap}
        call    {func}

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Lemit_done
        la      a0, {output_label}
        mv      a1, s0
        call    .Lemit_bytes

.Lemit_done:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}

        .section .rodata.input, "a", @progbits
plaintext:
        .byte   {_byte_list(input_data)}
token:
        .byte   {_byte_list(input_data)}

        .section .data.entry, "aw", @progbits
        .balign 4
entry:
        .byte   {_byte_list(_entry_bytes(valid, status))}

        .section .bss.output, "aw", @nobits
        .balign 4
token_out:
        .skip   {LINK_SESSION_TOKEN_MAX}
plaintext_out:
        .skip   {LINK_SESSION_PLAINTEXT_MAX}
"""


def _build_test_elf(
    tmp_path: Path,
    *,
    func: str,
    input_data: bytes,
    input_len: int,
    cap: int,
    valid: int,
    status: int,
) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / f"{func}_harness.S"
    harness.write_text(
        _harness_asm(
            func=func,
            input_data=input_data,
            input_len=input_len,
            cap=cap,
            valid=valid,
            status=status,
        ),
        encoding="utf-8",
    )

    objects: list[Path] = []
    for idx, src in enumerate((harness, *(REPO_ROOT / s for s in ASM_SOURCES))):
        obj = tmp_path / f"{idx:02d}_{Path(src).stem}.o"
        _run([
            as_bin,
            "-march=rv32imac",
            "-mabi=ilp32",
            "--defsym",
            "TARGET_QEMU_VIRT=1",
            "-I",
            str(REPO_ROOT / "src" / "include"),
            "-o",
            str(obj),
            str(src),
        ])
        objects.append(obj)

    elf = tmp_path / f"{func}.elf"
    _run([
        ld_bin,
        "-nostdlib",
        "-static",
        "--no-warn-rwx-segments",
        "-T",
        str(REPO_ROOT / "toolchain" / "qemu-virt.ld"),
        "-o",
        str(elf),
        *(str(obj) for obj in objects),
    ])
    return elf


def _run_qemu(
    tmp_path: Path,
    *,
    func: str,
    input_data: bytes,
    input_len: int,
    cap: int,
    valid: int,
    status: int,
) -> bytes:
    cfg = target.TargetConfig(
        binary=_build_test_elf(
            tmp_path,
            func=func,
            input_data=input_data,
            input_len=input_len,
            cap=cap,
            valid=valid,
            status=status,
        )
    )
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(160):
            out.extend(emu.read(4096, timeout=0.5))
            if out.count(b"\n") >= 1:
                break
    return bytes(out).splitlines()[0]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def _parse_output(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, out_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    return ret, bytes.fromhex(out_hex.decode()) if out_hex else b""


def test_encrypt_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_session_encrypt") > 0


def test_decrypt_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_session_decrypt") > 0


def test_encrypt_calls_token_primitives(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_session_encrypt")
    assert "rng_bytes" in body
    assert "aes256_key_expand" in body
    assert "aes256_cbc_encrypt" in body
    assert "hmac_sha256" in body


def test_decrypt_authenticates_before_decrypting(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_session_decrypt")
    assert body.index("hmac_sha256") < body.index("aes256_cbc_decrypt")


@pytest.mark.parametrize("case", ENCRYPT_CASES, ids=[case.name for case in ENCRYPT_CASES])
def test_link_session_encrypt_qemu(tmp_path: Path, case: EncryptCase) -> None:
    ret, token = _parse_output(
        _run_qemu(
            tmp_path,
            func="link_session_encrypt",
            input_data=case.plaintext,
            input_len=len(case.plaintext),
            cap=case.cap,
            valid=case.valid,
            status=case.status,
        )
    )
    if case.expect_ret is not None:
        assert ret == case.expect_ret
        assert token == b""
        return

    padded_len = len(_pkcs7_pad(case.plaintext))
    assert ret == LINK_SESSION_TOKEN_OVERHEAD + padded_len
    assert len(token) == ret
    assert token == _expected_token_with_iv(case.plaintext, token[:16])


@pytest.mark.parametrize("case", DECRYPT_CASES, ids=[case.name for case in DECRYPT_CASES])
def test_link_session_decrypt_qemu(tmp_path: Path, case: DecryptCase) -> None:
    ret, plaintext = _parse_output(
        _run_qemu(
            tmp_path,
            func="link_session_decrypt",
            input_data=case.token,
            input_len=len(case.token),
            cap=case.cap,
            valid=case.valid,
            status=case.status,
        )
    )
    assert ret == case.expect_ret
    if ret >= 0:
        assert plaintext == case.expect_plaintext
    else:
        assert plaintext == b""


def test_python_token_oracle_round_trip() -> None:
    token = _token_for(b"oracle-check")
    ciphertext = token[16:-32]
    padded = _aes_cbc_decrypt(KEY_MATERIAL[32:], token[:16], ciphertext)
    pad = padded[-1]
    assert padded[:-pad] == b"oracle-check"
