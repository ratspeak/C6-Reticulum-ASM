"""Direct QEMU tests for milestone-7 channel envelopes."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/resource/channel_envelope_build.S",
    "src/resource/channel_envelope_parse.S",
)

HEADER_LEN = 6
MAX_PAYLOAD = 425
ENV_T_SIZE = 20


def _envelope(msgtype: int, sequence: int, payload: bytes) -> bytes:
    return (
        msgtype.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + len(payload).to_bytes(2, "big")
        + payload
    )


@dataclasses.dataclass(frozen=True)
class BuildCase:
    name: str
    msgtype: int
    sequence: int
    payload: bytes
    cap: int
    expect_ret: int | None = None
    null_payload: bool = False
    null_out: bool = False


@dataclasses.dataclass(frozen=True)
class ParseCase:
    name: str
    raw: bytes
    expect_ret: int
    expect_msgtype: int = 0
    expect_sequence: int = 0
    expect_payload: bytes = b""
    null_raw: bool = False
    null_out: bool = False


BUILD_CASES = (
    BuildCase("short", 0x1234, 0x0102, b"hello", 64),
    BuildCase("empty", 0x0001, 0x0000, b"", HEADER_LEN),
    BuildCase("max-payload", 0xABCD, 0xFFFF, bytes((i * 7) & 0xFF for i in range(MAX_PAYLOAD)), HEADER_LEN + MAX_PAYLOAD),
    BuildCase("cap-overflow", 0x1234, 0x0102, b"hello", HEADER_LEN + 4, -2),
    BuildCase("payload-overflow", 0x1234, 0x0102, b"A" * (MAX_PAYLOAD + 1), HEADER_LEN + MAX_PAYLOAD + 1, -2),
    BuildCase("msgtype-overflow", 0x10000, 0, b"", HEADER_LEN, -1),
    BuildCase("sequence-overflow", 0, 0x10000, b"", HEADER_LEN, -1),
    BuildCase("null-payload-nonzero", 1, 2, b"abc", 32, -1, null_payload=True),
    BuildCase("null-out", 1, 2, b"abc", 32, -1, null_out=True),
)

PARSE_VALID_PAYLOAD = b"channel-data"
PARSE_CASES = (
    ParseCase("short", _envelope(0x1234, 0x0102, PARSE_VALID_PAYLOAD), 0, 0x1234, 0x0102, PARSE_VALID_PAYLOAD),
    ParseCase("empty", _envelope(0x0001, 0x0000, b""), 0, 0x0001, 0x0000, b""),
    ParseCase("truncated-header", b"\x00\x01\x00", -1),
    ParseCase("length-mismatch", _envelope(0x1234, 0x0102, b"abc")[:-1], -1),
    ParseCase("payload-overflow", _envelope(0x1234, 0x0102, b"A" * (MAX_PAYLOAD + 1)), -1),
    ParseCase("null-raw", _envelope(0x1234, 0x0102, b""), -1, null_raw=True),
    ParseCase("null-out", _envelope(0x1234, 0x0102, b""), -1, null_out=True),
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
7:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 7b
        sb      a0, 0(t0)
        ret
"""


def _build_harness(case: BuildCase) -> str:
    payload_arg = "mv      a2, zero" if case.null_payload else "la      a2, payload"
    out_arg = "mv      a4, zero" if case.null_out else "la      a4, raw_out"
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

        li      a0, {case.msgtype}
        li      a1, {case.sequence}
        {payload_arg}
        li      a3, {len(case.payload)}
        {out_arg}
        li      a5, {case.cap}
        call    channel_envelope_build
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, raw_out
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
payload:
        .byte   {_byte_list(case.payload)}

        .section .bss.output, "aw", @nobits
        .balign 4
raw_out:
        .skip   {HEADER_LEN + MAX_PAYLOAD}
"""


def _parse_harness(case: ParseCase) -> str:
    raw_arg = "mv      a0, zero" if case.null_raw else "la      a0, raw"
    out_arg = "mv      a2, zero" if case.null_out else "la      a2, parsed"
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

        {raw_arg}
        li      a1, {len(case.raw)}
        {out_arg}
        call    channel_envelope_parse
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, parsed
        li      a1, {ENV_T_SIZE}
        call    .Lemit_bytes
        li      a0, 58
        call    .Lputc
        la      t1, parsed
        lw      t0, 12(t1)
        la      a0, raw
        addi    a0, a0, {HEADER_LEN}
        mv      a1, t0
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
raw:
        .byte   {_byte_list(case.raw)}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   {ENV_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "channel_envelope_harness.S"
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

    elf = tmp_path / "channel_envelope.elf"
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
    return int.from_bytes(data[off:off + 4], "little")


def test_build_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "channel_envelope_build") > 0


def test_parse_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "channel_envelope_parse") > 0


@pytest.mark.parametrize("case", BUILD_CASES, ids=[c.name for c in BUILD_CASES])
def test_channel_envelope_build_qemu(tmp_path: Path, case: BuildCase) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _build_harness(case)))
    if case.expect_ret is not None:
        assert ret == case.expect_ret
        assert outputs == []
        return
    expected = _envelope(case.msgtype, case.sequence, case.payload)
    assert ret == len(expected)
    assert outputs == [expected]


@pytest.mark.parametrize("case", PARSE_CASES, ids=[c.name for c in PARSE_CASES])
def test_channel_envelope_parse_qemu(tmp_path: Path, case: ParseCase) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _parse_harness(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert outputs == []
        return
    parsed, payload = outputs
    assert _u32le(parsed, 0) == len(case.raw)
    assert _u32le(parsed, 4) == case.expect_msgtype
    assert _u32le(parsed, 8) == case.expect_sequence
    assert _u32le(parsed, 12) == len(case.expect_payload)
    assert payload == case.expect_payload
