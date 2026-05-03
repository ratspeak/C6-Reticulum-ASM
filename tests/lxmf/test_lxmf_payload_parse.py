"""Direct QEMU tests for LXMF payload parsing."""

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

ASM_SOURCES = ("src/lxmf/lxmf_payload_parse.S",)

MAX_TITLE = 64
MAX_CONTENT = 255
MAX_FIELDS = 64
MAX_PAYLOAD = 397
MAX_STAMPED = 431
STAMP_MAX = 32
PARSED_SIZE = 456


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    raw: bytes
    expect_ret: int = 0
    null_raw: bool = False
    null_out: bool = False


def _payload(items: list[object]) -> bytes:
    return msgpack.packb(items)


NO_STAMP = _payload([1.5, b"Title", b"Body", {}])
STAMP16 = bytes([0x95]) + NO_STAMP[1:] + b"\xc4\x10" + (b"\x11" * 16)
STAMP32 = bytes([0x95]) + NO_STAMP[1:] + b"\xc4\x20" + (b"\x22" * 32)

CASES = (
    Case("basic", NO_STAMP),
    Case("custom-fields", _payload([1700000000.0, b"", b"", {0xFB: b"abc"}])),
    Case("max-bounds", _payload([1.5, bytes(range(MAX_TITLE)), bytes(range(MAX_CONTENT)), {0xFB: b"A" * 58}])),
    Case("map16-fields", _payload([1.5, b"T", b"C", {i: i for i in range(16)}])),
    Case("stamp16", STAMP16),
    Case("stamp32", STAMP32),
    Case("null-raw", b"", -1, null_raw=True),
    Case("null-out", NO_STAMP, -1, null_out=True),
    Case("raw-overflow", bytes(MAX_STAMPED + 1), -2),
    Case("empty", b"", -1),
    Case("bad-array-marker", b"\x93", -1),
    Case("truncated-timestamp", b"\x94\xcb\x00", -1),
    Case("title-as-str", msgpack.packb([1.5, "Title", b"Body", {}]), -1),
    Case("title-overflow", _payload([1.5, b"A" * (MAX_TITLE + 1), b"", {}]), -2),
    Case("content-bin16-rejected", _payload([1.5, b"", bytes(range(256)), {}]), -1),
    Case("fields-overflow", _payload([1.5, b"", b"", {0xFB: b"A" * 60}]), -2),
    Case("nested-field-rejected", _payload([1.5, b"", b"", {1: [2]}]), -1),
    Case("trailing-byte", NO_STAMP + b"\x00", -1),
    Case("bad-stamp-marker", bytes([0x95]) + NO_STAMP[1:] + b"\xc0", -1),
    Case("empty-stamp", bytes([0x95]) + NO_STAMP[1:] + b"\xc4\x00", -1),
    Case("stamp-overflow", bytes([0x95]) + NO_STAMP[1:] + b"\xc4\x21" + (b"\x33" * 33), -2),
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

.Lemit_sep:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      a0, 58
        call    .Lputc
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lemit_ptr_len:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        call    .Lemit_bytes
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
    raw_ptr = "mv      a0, zero" if case.null_raw else "la      a0, payload_raw"
    out_ptr = "mv      a2, zero" if case.null_out else "la      a2, parsed"
    return f"""
        .include "lxmf.S"

        .section .text._reset, "ax", @progbits
        .global _reset
        .type   _reset, @function
_reset:
        la      sp, __stack_top

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

        {raw_ptr}
        li      a1, {len(case.raw)}
        {out_ptr}
        call    lxmf_payload_parse
        mv      s0, a0
        call    .Lemit_hex32
        blt     s0, zero, .Ldone

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_FLAGS(t0)
        call    .Lemit_hex32

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_RAW_LEN(t0)
        call    .Lemit_hex32

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN(t0)
        call    .Lemit_hex32

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_TIMESTAMP_BE_PTR(t0)
        li      a1, 8
        call    .Lemit_ptr_len

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_TITLE_PTR(t0)
        lw      a1, LXMF_PAYLOAD_PARSED_OFF_TITLE_LEN(t0)
        call    .Lemit_ptr_len

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_CONTENT_PTR(t0)
        lw      a1, LXMF_PAYLOAD_PARSED_OFF_CONTENT_LEN(t0)
        call    .Lemit_ptr_len

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_FIELDS_PTR(t0)
        lw      a1, LXMF_PAYLOAD_PARSED_OFF_FIELDS_LEN(t0)
        call    .Lemit_ptr_len

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_STAMP_PTR(t0)
        lw      a1, LXMF_PAYLOAD_PARSED_OFF_STAMP_LEN(t0)
        call    .Lemit_ptr_len

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_PTR(t0)
        lw      a1, LXMF_PAYLOAD_PARSED_OFF_WITHOUT_STAMP_LEN(t0)
        call    .Lemit_ptr_len

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
payload_raw:
        .byte   {_byte_list(case.raw)}

        .section .bss.output, "aw", @nobits
        .balign 4
parsed:
        .skip   {PARSED_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_payload_parse_harness.S"
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

    elf = tmp_path / "lxmf_payload_parse.elf"
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


def _u32(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _expected(raw: bytes) -> tuple[int, int, bytes, bytes, bytes, bytes, bytes, bytes]:
    unpacked = msgpack.unpackb(raw)
    stamp = unpacked[4] if len(unpacked) > 4 else b""
    without = msgpack.packb(unpacked[:4]) if len(unpacked) > 4 else raw
    fields = msgpack.packb(unpacked[3])
    return (
        1 if len(unpacked) > 4 else 0,
        len(raw),
        struct.pack(">d", unpacked[0]),
        unpacked[1],
        unpacked[2],
        fields,
        stamp,
        without,
    )


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_payload_parse") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_payload_parse_qemu(tmp_path: Path, case: Case) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _harness(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert outputs == []
        return

    flags, raw_len, without_len, ts, title, content, fields, stamp, without = outputs
    exp_flags, exp_raw_len, exp_ts, exp_title, exp_content, exp_fields, exp_stamp, exp_without = _expected(case.raw)

    assert _u32(flags) == exp_flags
    assert _u32(raw_len) == exp_raw_len
    assert _u32(without_len) == len(exp_without)
    assert ts == exp_ts
    assert title == exp_title
    assert content == exp_content
    assert fields == exp_fields
    assert stamp == exp_stamp
    assert without == exp_without


def test_stamped_known_vector() -> None:
    expected_without = msgpack.packb([1.5, b"Title", b"Body", {}])
    assert STAMP16.startswith(b"\x95")
    assert expected_without == NO_STAMP
