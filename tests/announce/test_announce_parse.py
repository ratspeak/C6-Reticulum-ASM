"""Direct QEMU tests for src/announce/announce_parse.S."""

from __future__ import annotations

import dataclasses
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/announce/announce_parse.S",
    "src/packet/packet_parse_header.S",
)

ANNOUNCE_BASE_RAW_LEN = 167
ANNOUNCE_HEADER_LEN = 19
ANNOUNCE_H2_HEADER_LEN = 35
ANNOUNCE_FIXED_FIELD_LEN = 164
ANNOUNCE_RX_T_SIZE = 180
RETICULUM_MDU = 484
MAX_APP_DATA = RETICULUM_MDU - ANNOUNCE_BASE_RAW_LEN


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    raw_packet: bytes
    raw_len: int | None = None
    null_raw: bool = False
    null_out: bool = False


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 37) & 0xFF for i in range(length))


def _announce_packet(app_data: bytes = b"", *, hops: int = 0) -> bytes:
    destination_hash = _bytes_from(0x10, oracle.DESTINATION_HASH_LEN)
    public_key = _bytes_from(0x30, oracle.IDENTITY_PUBLIC_LEN)
    name_hash = _bytes_from(0x70, oracle.DESTINATION_NAME_HASH_LEN)
    random_hash = _bytes_from(0x90, oracle.ANNOUNCE_RANDOM_HASH_LEN)
    signature = _bytes_from(0xB0, oracle.ANNOUNCE_SIGNATURE_LEN)
    payload = oracle.announce_payload(
        public_key, name_hash, random_hash, signature, app_data
    )
    return (
        bytes([oracle.HEADER_1_ANNOUNCE_FLAGS, hops & 0xFF])
        + destination_hash
        + bytes([oracle.PACKET_CONTEXT_NONE])
        + payload
    )


def _announce_h2_packet(app_data: bytes = b"", *, hops: int = 0) -> bytes:
    raw = _announce_packet(app_data, hops=hops)
    transport_id = _bytes_from(0xA0, oracle.DESTINATION_HASH_LEN)
    return bytes([0x51, raw[1]]) + transport_id + raw[2:]


VALID_CASES = (
    Case("empty-app", _announce_packet()),
    Case("nonzero-hops", _announce_packet(b"hello announce", hops=7)),
    Case("header2-transport", _announce_h2_packet(b"transport announce", hops=3)),
    Case("max-app", _announce_packet(_bytes_from(0x44, MAX_APP_DATA))),
)


def _mutated(raw: bytes, offset: int, value: int) -> bytes:
    out = bytearray(raw)
    out[offset] = value
    return bytes(out)


BASE_PACKET = _announce_packet(b"payload")

INVALID_CASES = (
    Case("null-raw", BASE_PACKET, null_raw=True),
    Case("null-out", BASE_PACKET, null_out=True),
    Case("zero-len", BASE_PACKET, raw_len=0),
    Case("header-only", BASE_PACKET[:ANNOUNCE_HEADER_LEN]),
    Case("truncated-signature", BASE_PACKET[:ANNOUNCE_BASE_RAW_LEN - 1]),
    Case("bad-flags-data", _mutated(BASE_PACKET, 0, 0x00)),
    Case("bad-flags-header2", _mutated(BASE_PACKET, 0, 0x41)),
    Case("bad-context", _mutated(BASE_PACKET, 18, 0x01)),
    Case(
        "over-mdu",
        _announce_packet(_bytes_from(0x55, MAX_APP_DATA + 1)),
    ),
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


def _harness_asm(case: Case) -> str:
    raw_len = len(case.raw_packet) if case.raw_len is None else case.raw_len
    raw_ptr = "mv      a0, zero" if case.null_raw else "la      a0, raw_packet"
    out_ptr = "mv      a2, zero" if case.null_out else "la      a2, parsed"
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

        {raw_ptr}
        li      a1, {raw_len}
        {out_ptr}
        call    announce_parse

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Lemit_done

        la      s1, parsed
        lw      a0, 0(s1)
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        lw      a0, 4(s1)
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        lw      a0, 8(s1)
        mv      s2, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc

        addi    a0, s1, 12
        li      a1, {ANNOUNCE_FIXED_FIELD_LEN}
        call    .Lemit_bytes
        li      a0, 58
        call    .Lputc

        lw      s3, 176(s1)
        beqz    s2, .Lemit_app
        li      t0, 0xa5
        sb      t0, 0(s3)
.Lemit_app:
        mv      a0, s3
        mv      a1, s2
        call    .Lemit_bytes

.Lemit_done:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

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

        .size   _reset, . - _reset

        .section .data.raw_packet, "aw", @progbits
        .balign 4
raw_packet:
        .byte   {_byte_list(case.raw_packet)}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   {ANNOUNCE_RX_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, case: Case) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "announce_parse_harness.S"
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

    elf = tmp_path / "announce_parse.elf"
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


def _run_qemu(elf: Path) -> bytes:
    cfg = target.TargetConfig(binary=elf)
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(120):
            out.extend(emu.read(1024, timeout=0.5))
            if b"\n" in out:
                break
    return bytes(out)


@dataclasses.dataclass(frozen=True)
class ParsedOutput:
    ret: int
    raw_len: int = 0
    payload_len: int = 0
    app_data_len: int = 0
    fixed_fields: bytes = b""
    app_view: bytes = b""


def _parse_output(output: bytes) -> ParsedOutput:
    line = output.splitlines()[0]
    parts = line.split(b":")
    ret_u32 = int(parts[0], 16)
    ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
    if ret < 0:
        return ParsedOutput(ret=ret)
    assert len(parts) == 6, line
    return ParsedOutput(
        ret=ret,
        raw_len=int(parts[1], 16),
        payload_len=int(parts[2], 16),
        app_data_len=int(parts[3], 16),
        fixed_fields=bytes.fromhex(parts[4].decode()),
        app_view=bytes.fromhex(parts[5].decode()) if parts[5] else b"",
    )


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "announce_parse") > 0


def test_calls_packet_parse_header(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_parse")
    assert "packet_parse_header" in body


def test_static_length_and_error_shape(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_parse")
    assert re.search(r"\bli\b\s+\w+,\s*167\b", body), body
    assert re.search(r"\bli\b\s+\w+,\s*484\b", body), body
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


@pytest.mark.parametrize("case", VALID_CASES, ids=[c.name for c in VALID_CASES])
def test_announce_parse_valid_qemu(tmp_path: Path, case: Case) -> None:
    result = _parse_output(_run_qemu(_build_test_elf(tmp_path, case)))
    expected_raw = (
        bytes([0x01, case.raw_packet[1]]) + case.raw_packet[18:]
        if case.raw_packet[0] == 0x51
        else case.raw_packet
    )
    expected_payload_off = (
        ANNOUNCE_H2_HEADER_LEN if case.raw_packet[0] == 0x51 else ANNOUNCE_HEADER_LEN
    )
    expected = oracle.announce_parse(expected_raw)

    fixed = (
        expected.destination_hash
        + expected.public_key
        + expected.name_hash
        + expected.random_hash
        + expected.signature
    )
    app_view = expected.app_data
    if app_view:
        app_view = bytes([0xA5]) + app_view[1:]

    assert result.ret == 0
    assert result.raw_len == len(case.raw_packet)
    assert result.payload_len == len(case.raw_packet) - expected_payload_off
    assert result.app_data_len == len(expected.app_data)
    assert result.fixed_fields == fixed
    assert result.app_view == app_view


@pytest.mark.parametrize("case", INVALID_CASES, ids=[c.name for c in INVALID_CASES])
def test_announce_parse_rejects_invalid_qemu(tmp_path: Path, case: Case) -> None:
    if not case.null_raw and not case.null_out:
        with pytest.raises(ValueError):
            oracle.announce_parse(case.raw_packet[:case.raw_len])

    result = _parse_output(_run_qemu(_build_test_elf(tmp_path, case)))
    assert result.ret == -1
