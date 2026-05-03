"""Direct QEMU tests for milestone-6 link_derive_keys."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/link/link_derive_keys.S",
    "src/crypto/hkdf/hkdf_extract.S",
    "src/crypto/hkdf/hkdf_expand.S",
    "src/crypto/hmac/hmac_sha256.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/hkdf.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
)

SHARED_SECRET_SIZE = 32
KEY_MATERIAL_SIZE = 64


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 19) & 0xFF for i in range(length))


def _hkdf_sha256(shared_secret: bytes, transcript: bytes, length: int = 64) -> bytes:
    prk = hmac.new(transcript, shared_secret, hashlib.sha256).digest()
    block = b""
    out = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    shared_secret: bytes
    transcript: bytes
    expect_ret: int = 0
    null_shared: bool = False
    null_transcript: bool = False
    null_out: bool = False
    transcript_len: int | None = None


VALID_CASES = (
    Case("link-id-salt", _bytes_from(0x10, 32), _bytes_from(0x80, 16)),
    Case(
        "request-transcript-salt",
        _bytes_from(0x33, 32),
        bytes([0x02]) + _bytes_from(0x44, 16) + b"\x00" + _bytes_from(0x55, 64),
    ),
)

INVALID_CASES = (
    Case("null-shared", _bytes_from(0x10, 32), _bytes_from(0x80, 16), -1, null_shared=True),
    Case(
        "null-transcript",
        _bytes_from(0x10, 32),
        _bytes_from(0x80, 16),
        -1,
        null_transcript=True,
    ),
    Case(
        "zero-transcript-len",
        _bytes_from(0x10, 32),
        _bytes_from(0x80, 16),
        -1,
        transcript_len=0,
    ),
    Case("null-out", _bytes_from(0x10, 32), _bytes_from(0x80, 16), -1, null_out=True),
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
        sb      a0, 0(t0)
        ret
"""


def _harness_asm(case: Case) -> str:
    transcript_len = len(case.transcript) if case.transcript_len is None else case.transcript_len
    shared_arg = "mv      a0, zero" if case.null_shared else "la      a0, shared_secret"
    transcript_arg = (
        "mv      a1, zero" if case.null_transcript else "la      a1, transcript"
    )
    out_arg = "mv      a3, zero" if case.null_out else "la      a3, key_material"
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

        {shared_arg}
        {transcript_arg}
        li      a2, {transcript_len}
        {out_arg}
        call    link_derive_keys

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Lemit_done
        la      a0, key_material
        li      a1, {KEY_MATERIAL_SIZE}
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

        .section .rodata.shared_secret, "a", @progbits
shared_secret:
        .byte   {_byte_list(case.shared_secret)}
transcript:
        .byte   {_byte_list(case.transcript)}

        .section .bss.key_material, "aw", @nobits
        .balign 4
key_material:
        .skip   {KEY_MATERIAL_SIZE}
"""


def _build_test_elf(tmp_path: Path, case: Case) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "link_derive_keys_harness.S"
    harness.write_text(_harness_asm(case), encoding="utf-8")

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

    elf = tmp_path / "link_derive_keys.elf"
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


def _run_qemu(tmp_path: Path, case: Case) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, case))
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(120):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= 1:
                break
    return bytes(out).splitlines()[0]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def _parse_output(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, key_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    return ret, bytes.fromhex(key_hex.decode()) if key_hex else b""


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_derive_keys") > 0


def test_calls_hkdf_primitives(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_derive_keys")
    assert "hkdf_extract" in body
    assert "hkdf_expand" in body


@pytest.mark.parametrize("case", VALID_CASES, ids=[case.name for case in VALID_CASES])
def test_link_derive_keys_valid_qemu(tmp_path: Path, case: Case) -> None:
    ret, key_material = _parse_output(_run_qemu(tmp_path, case))
    assert ret == 0
    assert key_material == _hkdf_sha256(case.shared_secret, case.transcript)


@pytest.mark.parametrize("case", INVALID_CASES, ids=[case.name for case in INVALID_CASES])
def test_link_derive_keys_rejects_invalid_qemu(tmp_path: Path, case: Case) -> None:
    ret, key_material = _parse_output(_run_qemu(tmp_path, case))
    assert ret == case.expect_ret
    assert key_material == b""
