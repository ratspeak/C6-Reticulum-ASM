"""Direct QEMU tests for milestone-6 link request build/parse."""

from __future__ import annotations

import dataclasses
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_BUILD_SOURCES = (
    "src/link/link_request_build.S",
)

ASM_PARSE_SOURCES = (
    "src/link/link_request_parse.S",
    "src/packet/packet_parse_header.S",
)

LINK_REQUEST_T_SIZE = 92
LR_OFF_RAW_LEN = 0
LR_OFF_MTU = 4
LR_OFF_MODE = 8
LR_OFF_DEST_HASH = 12
LR_OFF_X25519_PUB = 28
LR_OFF_ED25519_PUB = 60


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 31) & 0xFF for i in range(length))


DEST_HASH = _bytes_from(0x11, oracle.DESTINATION_HASH_LEN)
X25519_PUBLIC = _bytes_from(0x42, oracle.X25519_KEY_LEN)
ED25519_PUBLIC = _bytes_from(0x83, oracle.ED25519_KEY_LEN)
VALID_REQUEST = oracle.link_request_build(DEST_HASH, X25519_PUBLIC, ED25519_PUBLIC)


@dataclasses.dataclass(frozen=True)
class BuildCase:
    name: str
    capacity: int = oracle.LINK_REQUEST_RAW_LEN
    expect_ret: int = oracle.LINK_REQUEST_RAW_LEN
    null_dest: bool = False
    null_x25519: bool = False
    null_ed25519: bool = False
    null_out: bool = False


BUILD_CASES = (
    BuildCase("exact-capacity"),
    BuildCase("extra-capacity", capacity=oracle.LINK_REQUEST_RAW_LEN + 5),
    BuildCase(
        "overflow",
        capacity=oracle.LINK_REQUEST_RAW_LEN - 1,
        expect_ret=-2,
    ),
    BuildCase("null-dest", expect_ret=-1, null_dest=True),
    BuildCase("null-x25519", expect_ret=-1, null_x25519=True),
    BuildCase("null-ed25519", expect_ret=-1, null_ed25519=True),
    BuildCase("null-out", expect_ret=-1, null_out=True),
)


@dataclasses.dataclass(frozen=True)
class ParseCase:
    name: str
    raw_packet: bytes
    expect_ret: int = 0
    raw_len: int | None = None
    null_raw: bool = False
    null_out: bool = False


def _mutated(raw: bytes, offset: int, value: int) -> bytes:
    out = bytearray(raw)
    out[offset] = value
    return bytes(out)


VALID_HOPS_REQUEST = _mutated(VALID_REQUEST.raw_packet, 1, 7)

PARSE_VALID_CASES = (
    ParseCase("current-default", VALID_REQUEST.raw_packet),
    ParseCase("nonzero-hops", VALID_HOPS_REQUEST),
)

PARSE_INVALID_CASES = (
    ParseCase("null-raw", VALID_REQUEST.raw_packet, expect_ret=-1, null_raw=True),
    ParseCase("null-out", VALID_REQUEST.raw_packet, expect_ret=-1, null_out=True),
    ParseCase("zero-len", VALID_REQUEST.raw_packet, expect_ret=-1, raw_len=0),
    ParseCase(
        "truncated",
        VALID_REQUEST.raw_packet[: oracle.LINK_REQUEST_RAW_LEN - 1],
        expect_ret=-1,
    ),
    ParseCase(
        "legacy-no-signalling",
        VALID_REQUEST.raw_packet[: oracle.LINK_REQUEST_RAW_LEN - 3],
        expect_ret=-1,
    ),
    ParseCase(
        "strict-extra-byte",
        VALID_REQUEST.raw_packet + b"\x00",
        expect_ret=-1,
    ),
    ParseCase(
        "over-mdu",
        VALID_REQUEST.raw_packet
        + _bytes_from(0x22, oracle.RETICULUM_MDU + 1 - oracle.LINK_REQUEST_RAW_LEN),
        expect_ret=-1,
    ),
    ParseCase(
        "bad-flags-data",
        _mutated(VALID_REQUEST.raw_packet, 0, 0x00),
        expect_ret=-1,
    ),
    ParseCase(
        "bad-flags-header2",
        _mutated(VALID_REQUEST.raw_packet, 0, 0x42),
        expect_ret=-1,
    ),
    ParseCase(
        "bad-context",
        _mutated(VALID_REQUEST.raw_packet, 18, 0x01),
        expect_ret=-1,
    ),
    ParseCase(
        "bad-mode",
        _mutated(VALID_REQUEST.raw_packet, 83, 0x40),
        expect_ret=-1,
    ),
    ParseCase(
        "bad-mtu",
        _mutated(VALID_REQUEST.raw_packet, 85, 0xF5),
        expect_ret=-1,
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


def _build_harness_asm(case: BuildCase) -> str:
    dest_arg = "mv      a0, zero" if case.null_dest else "la      a0, dest_hash"
    x_arg = "mv      a1, zero" if case.null_x25519 else "la      a1, x25519_public"
    sig_arg = "mv      a2, zero" if case.null_ed25519 else "la      a2, ed25519_public"
    out_arg = "mv      a3, zero" if case.null_out else "la      a3, raw_out"
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

        {dest_arg}
        {x_arg}
        {sig_arg}
        {out_arg}
        li      a4, {case.capacity}
        call    link_request_build

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Lemit_done
        la      a0, raw_out
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

        .section .rodata.dest_hash, "a", @progbits
dest_hash:
        .byte   {_byte_list(DEST_HASH)}
x25519_public:
        .byte   {_byte_list(X25519_PUBLIC)}
ed25519_public:
        .byte   {_byte_list(ED25519_PUBLIC)}

        .section .bss.raw_out, "aw", @nobits
        .balign 4
raw_out:
        .skip   {oracle.LINK_REQUEST_RAW_LEN}
"""


def _parse_harness_asm(case: ParseCase) -> str:
    raw_len = len(case.raw_packet) if case.raw_len is None else case.raw_len
    raw_arg = "mv      a0, zero" if case.null_raw else "la      a0, raw_packet"
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
        li      a1, {raw_len}
        {out_arg}
        call    link_request_parse

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Lemit_done

        la      s1, parsed
        lw      a0, {LR_OFF_RAW_LEN}(s1)
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        lw      a0, {LR_OFF_MTU}(s1)
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        lw      a0, {LR_OFF_MODE}(s1)
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        addi    a0, s1, {LR_OFF_DEST_HASH}
        li      a1, {oracle.DESTINATION_HASH_LEN + oracle.X25519_KEY_LEN + oracle.ED25519_KEY_LEN}
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

        .section .rodata.raw_packet, "a", @progbits
raw_packet:
        .byte   {_byte_list(case.raw_packet)}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   {LINK_REQUEST_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, harness_asm: str, sources: tuple[str, ...]) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "link_request_harness.S"
    harness.write_text(harness_asm, encoding="utf-8")

    objects: list[Path] = []
    for idx, src in enumerate((harness, *(REPO_ROOT / s for s in sources))):
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

    elf = tmp_path / "link_request.elf"
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


def _run_qemu(tmp_path: Path, harness_asm: str, sources: tuple[str, ...]) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, harness_asm, sources))
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


def _parse_build_output(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, raw_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    return ret, bytes.fromhex(raw_hex.decode()) if raw_hex else b""


@dataclasses.dataclass(frozen=True)
class ParsedRequest:
    ret: int
    raw_len: int = 0
    mtu: int = 0
    mode: int = 0
    fields: bytes = b""


def _parse_parse_output(line: bytes) -> ParsedRequest:
    parts = line.split(b":")
    ret = _parse_ret(parts[0])
    if ret < 0:
        return ParsedRequest(ret=ret)
    assert len(parts) == 5, line
    return ParsedRequest(
        ret=ret,
        raw_len=int(parts[1], 16),
        mtu=int(parts[2], 16),
        mode=int(parts[3], 16),
        fields=bytes.fromhex(parts[4].decode()),
    )


def test_functions_exist(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_request_build") > 0
    assert build.symbol_address(artifacts.elf, "link_request_parse") > 0


def test_parse_calls_packet_parse_header(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_request_parse")
    assert "packet_parse_header" in body


def test_oracle_uses_current_upstream_signalling() -> None:
    assert oracle.link_request_signalling() == bytes([0x20, 0x01, 0xF4])
    assert VALID_REQUEST.raw_packet[0] == oracle.HEADER_1_LINKREQUEST_FLAGS
    assert len(VALID_REQUEST.raw_packet) == oracle.LINK_REQUEST_RAW_LEN
    parsed = oracle.link_request_parse(VALID_REQUEST.raw_packet)
    assert parsed.mtu == oracle.LINK_REQUEST_MTU
    assert parsed.mode == oracle.LINK_REQUEST_MODE_AES256_CBC


@pytest.mark.parametrize("case", BUILD_CASES, ids=[case.name for case in BUILD_CASES])
def test_link_request_build_qemu(tmp_path: Path, case: BuildCase) -> None:
    line = _run_qemu(tmp_path, _build_harness_asm(case), ASM_BUILD_SOURCES)
    ret, raw = _parse_build_output(line)
    assert ret == case.expect_ret
    if ret >= 0:
        assert raw == VALID_REQUEST.raw_packet


@pytest.mark.parametrize(
    "case", PARSE_VALID_CASES, ids=[case.name for case in PARSE_VALID_CASES]
)
def test_link_request_parse_valid_qemu(tmp_path: Path, case: ParseCase) -> None:
    line = _run_qemu(tmp_path, _parse_harness_asm(case), ASM_PARSE_SOURCES)
    result = _parse_parse_output(line)
    expected = oracle.link_request_parse(case.raw_packet)
    assert result.ret == 0
    assert result.raw_len == len(case.raw_packet)
    assert result.mtu == expected.mtu
    assert result.mode == expected.mode
    assert (
        result.fields
        == expected.destination_hash + expected.x25519_public + expected.ed25519_public
    )


@pytest.mark.parametrize(
    "case", PARSE_INVALID_CASES, ids=[case.name for case in PARSE_INVALID_CASES]
)
def test_link_request_parse_rejects_invalid_qemu(
    tmp_path: Path, case: ParseCase
) -> None:
    line = _run_qemu(tmp_path, _parse_harness_asm(case), ASM_PARSE_SOURCES)
    result = _parse_parse_output(line)
    assert result.ret == case.expect_ret


def test_link_request_struct_offsets() -> None:
    parsed = bytearray(LINK_REQUEST_T_SIZE)
    struct.pack_into("<III", parsed, 0, 86, 500, 1)
    parsed[LR_OFF_DEST_HASH:LR_OFF_DEST_HASH + 16] = DEST_HASH
    parsed[LR_OFF_X25519_PUB:LR_OFF_X25519_PUB + 32] = X25519_PUBLIC
    parsed[LR_OFF_ED25519_PUB:LR_OFF_ED25519_PUB + 32] = ED25519_PUBLIC
    assert parsed[12:92] == DEST_HASH + X25519_PUBLIC + ED25519_PUBLIC


def test_build_source_writes_current_signalling(artifacts: build.BuildArtifacts) -> None:
    src = (REPO_ROOT / "src" / "link" / "link_request_build.S").read_text(
        encoding="utf-8"
    )
    assert "LINK_SIGNAL_BYTE0" in src
    assert "LINK_SIGNAL_BYTE1" in src
    assert "LINK_SIGNAL_BYTE2" in src
