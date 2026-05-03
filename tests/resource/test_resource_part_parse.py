"""Direct QEMU tests for milestone-7 resource part parsing."""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/resource/resource_part_parse.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/sha256.S",
)

PART_MAX_LEN = 431
RANDOM_HASH_SIZE = 4
MAPHASH_SIZE = 4
PART_T_SIZE = 12


@dataclasses.dataclass(frozen=True)
class PartCase:
    name: str
    payload: bytes
    random_hash: bytes
    expect_ret: int
    null_payload: bool = False
    null_random_hash: bool = False
    null_out: bool = False


PART_CASES = (
    PartCase("short", b"resource-part", b"\x01\x02\x03\x04", 0),
    PartCase("empty", b"", b"\x10\x20\x30\x40", 0, null_payload=True),
    PartCase("max", bytes((i * 17 + 3) & 0xFF for i in range(PART_MAX_LEN)), b"RND0", 0),
    PartCase("overflow", bytes(PART_MAX_LEN + 1), b"\x01\x02\x03\x04", -2),
    PartCase("null-payload-nonzero", b"abc", b"\x01\x02\x03\x04", -1, null_payload=True),
    PartCase("null-random-hash", b"abc", b"\x01\x02\x03\x04", -1, null_random_hash=True),
    PartCase("null-out", b"abc", b"\x01\x02\x03\x04", -1, null_out=True),
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
5:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 5b
        sb      a0, 0(t0)
        ret
"""


def _harness_asm(case: PartCase) -> str:
    payload_arg = "mv      a0, zero" if case.null_payload else "la      a0, payload"
    random_arg = "mv      a2, zero" if case.null_random_hash else "la      a2, random_hash"
    out_arg = "mv      a3, zero" if case.null_out else "la      a3, parsed"
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

        {payload_arg}
        li      a1, {len(case.payload)}
        {random_arg}
        {out_arg}
        call    resource_part_parse
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, parsed
        li      a1, {PART_T_SIZE}
        call    .Lemit_bytes
        li      a0, 58
        call    .Lputc
        la      t1, parsed
        lw      a0, 4(t1)
        lw      a1, 0(t1)
        call    .Lemit_bytes
.Ldone:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc
.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}

        .section .rodata.input, "a", @progbits
payload:
        .byte   {_byte_list(case.payload)}
random_hash:
        .byte   {_byte_list(case.random_hash[:RANDOM_HASH_SIZE])}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   {PART_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "resource_part_parse_harness.S"
    harness.write_text(asm, encoding="utf-8")

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

    elf = tmp_path / "resource_part_parse.elf"
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


def _run_qemu(tmp_path: Path, asm: str) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, asm))
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


def _parse_line(line: bytes) -> tuple[int, list[bytes]]:
    parts = line.split(b":")
    ret = _parse_ret(parts[0])
    if ret < 0:
        return ret, []
    return ret, [bytes.fromhex(p.decode()) for p in parts[1:]]


def _u32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _maphash(payload: bytes, random_hash: bytes) -> bytes:
    return hashlib.sha256(payload + random_hash[:RANDOM_HASH_SIZE]).digest()[:MAPHASH_SIZE]


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "resource_part_parse") > 0


@pytest.mark.parametrize("case", PART_CASES, ids=[c.name for c in PART_CASES])
def test_resource_part_parse_qemu(tmp_path: Path, case: PartCase) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _harness_asm(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert outputs == []
        return

    parsed, payload = outputs
    assert _u32le(parsed, 0) == len(case.payload)
    assert parsed[8:12] == _maphash(case.payload, case.random_hash)
    assert payload == case.payload
