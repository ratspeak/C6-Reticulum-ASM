"""Direct QEMU tests for LXMF payload construction."""

from __future__ import annotations

import dataclasses
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))

import RNS.vendor.umsgpack as msgpack  # noqa: E402

ASM_SOURCES = ("src/lxmf/lxmf_payload_build.S",)

MAX_TITLE = 64
MAX_CONTENT = 255
MAX_FIELDS = 64
MAX_PAYLOAD = 397


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    timestamp: float
    title: bytes
    content: bytes
    fields: bytes = b""
    cap: int = MAX_PAYLOAD
    expect_ret: int | None = None
    null_input: bool = False
    null_out: bool = False
    null_timestamp: bool = False
    null_title_with_len: bool = False
    null_content_with_len: bool = False
    null_fields_with_len: bool = False


CUSTOM_FIELDS = msgpack.packb({0xFB: b"abc"})

CASES = (
    Case("empty-fields", 1700000000.0, b"Title", b"Body"),
    Case("empty-title-content", 1.5, b"", b""),
    Case("custom-fields", 1.5, b"Title", b"Body", CUSTOM_FIELDS),
    Case("max-title-content", 1.5, bytes(range(MAX_TITLE)), bytes(range(MAX_CONTENT))),
    Case("cap-overflow", 1.5, b"Title", b"Body", cap=8, expect_ret=-2),
    Case("title-overflow", 1.5, b"A" * (MAX_TITLE + 1), b"", expect_ret=-2),
    Case("content-overflow", 1.5, b"", b"B" * (MAX_CONTENT + 1), expect_ret=-2),
    Case("fields-overflow", 1.5, b"", b"", b"\x80" + b"x" * MAX_FIELDS, expect_ret=-2),
    Case("bad-fields-marker", 1.5, b"", b"", b"\xc0", expect_ret=-1),
    Case("truncated-map16-marker", 1.5, b"", b"", b"\xde", expect_ret=-1),
    Case("truncated-map16-header", 1.5, b"", b"", b"\xde\x00", expect_ret=-1),
    Case("truncated-map32-header", 1.5, b"", b"", b"\xdf\x00\x00\x00", expect_ret=-1),
    Case("null-input", 1.5, b"", b"", expect_ret=-1, null_input=True),
    Case("null-out", 1.5, b"", b"", expect_ret=-1, null_out=True),
    Case("null-timestamp", 1.5, b"", b"", expect_ret=-1, null_timestamp=True),
    Case("null-title-nonzero", 1.5, b"bad", b"", expect_ret=-1, null_title_with_len=True),
    Case("null-content-nonzero", 1.5, b"", b"bad", expect_ret=-1, null_content_with_len=True),
    Case("null-fields-nonzero", 1.5, b"", b"", b"\x80", expect_ret=-1, null_fields_with_len=True),
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


def _expected(case: Case) -> bytes:
    fields_obj = msgpack.unpackb(case.fields) if case.fields else {}
    return msgpack.packb([case.timestamp, case.title, case.content, fields_obj])


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


def _harness(case: Case) -> str:
    input_ptr = "mv      a0, zero" if case.null_input else "la      a0, payload_input"
    out_ptr = "mv      a1, zero" if case.null_out else "la      a1, payload_out"
    timestamp_ptr = "0" if case.null_timestamp else "timestamp_be"
    title_ptr = "0" if case.null_title_with_len else "title"
    content_ptr = "0" if case.null_content_with_len else "content"
    if case.null_fields_with_len:
        fields_ptr = "0"
        fields_len = len(case.fields)
    elif case.fields:
        fields_ptr = "fields"
        fields_len = len(case.fields)
    else:
        fields_ptr = "0"
        fields_len = 0
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

        {input_ptr}
        {out_ptr}
        li      a2, {case.cap}
        call    lxmf_payload_build
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, payload_out
        mv      a1, s0
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
timestamp_be:
        .byte   {_byte_list(struct.pack(">d", case.timestamp))}
title:
        .byte   {_byte_list(case.title)}
content:
        .byte   {_byte_list(case.content)}
fields:
        .byte   {_byte_list(case.fields)}

        .section .data.input, "aw", @progbits
        .balign 4
payload_input:
        .word   {timestamp_ptr}
        .word   {title_ptr}
        .word   {len(case.title)}
        .word   {content_ptr}
        .word   {len(case.content)}
        .word   {fields_ptr}
        .word   {fields_len}

        .section .bss.output, "aw", @nobits
        .balign 4
payload_out:
        .skip   {MAX_PAYLOAD}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_payload_build_harness.S"
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

    elf = tmp_path / "lxmf_payload_build.elf"
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


def _parse_line(line: bytes) -> tuple[int, bytes | None]:
    ret_hex, _, payload_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    if ret < 0:
        return ret, None
    return ret, bytes.fromhex(payload_hex.decode())


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_payload_build") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_payload_build_qemu(tmp_path: Path, case: Case) -> None:
    ret, payload = _parse_line(_run_qemu(tmp_path, _harness(case)))
    if case.expect_ret is not None:
        assert ret == case.expect_ret
        assert payload is None
        return
    expected = _expected(case)
    assert ret == len(expected)
    assert payload == expected


def test_known_upstream_vector() -> None:
    case = Case("vector", 1700000000.0, b"Title", b"Body")
    assert _expected(case).hex() == "94cb41d954fc40000000c4055469746c65c404426f647980"
