"""Direct QEMU tests for milestone-7 resource advertisement parsing."""

from __future__ import annotations

import dataclasses
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/resource/resource_advertisement_parse.S",
)

ADV_T_SIZE = 104
ADV_MAX_RAW_LEN = 431
ADV_MAX_PARTS = 64
PART_MAX_LEN = 431
HASH_SIZE = 32
RANDOM_HASH_SIZE = 4
MAPHASH_SIZE = 4

ADV_OFF_RAW_LEN = 0
ADV_OFF_TRANSFER_SIZE = 4
ADV_OFF_DATA_SIZE = 8
ADV_OFF_PART_COUNT = 12
ADV_OFF_FLAGS = 16
ADV_OFF_SEGMENT_INDEX = 20
ADV_OFF_TOTAL_SEGMENTS = 24
ADV_OFF_RESOURCE_HASH = 28
ADV_OFF_RANDOM_HASH = 60
ADV_OFF_ORIGINAL_HASH = 64
ADV_OFF_HASHMAP_LEN = 96


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 23) & 0xFF for i in range(length))


def _mp_key(ch: str) -> bytes:
    return b"\xa1" + ch.encode("ascii")


def _mp_uint(value: int) -> bytes:
    if 0 <= value <= 0x7F:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + bytes([value])
    if value <= 0xFFFF:
        return b"\xcd" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def _mp_bin(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"\xc4" + bytes([len(data)]) + data
    return b"\xc5" + len(data).to_bytes(2, "big") + data


def _advertisement(
    *,
    transfer_size: int,
    data_size: int,
    part_count: int,
    resource_hash: bytes,
    random_hash: bytes,
    original_hash: bytes | None = None,
    segment_index: int = 1,
    total_segments: int = 1,
    request_nil: bool = True,
    flags: int = 1,
    hashmap: bytes,
) -> bytes:
    original = resource_hash if original_hash is None else original_hash
    q = b"\xc0" if request_nil else _mp_uint(0)
    fields = (
        _mp_key("t") + _mp_uint(transfer_size),
        _mp_key("d") + _mp_uint(data_size),
        _mp_key("n") + _mp_uint(part_count),
        _mp_key("h") + _mp_bin(resource_hash),
        _mp_key("r") + _mp_bin(random_hash),
        _mp_key("o") + _mp_bin(original),
        _mp_key("i") + _mp_uint(segment_index),
        _mp_key("l") + _mp_uint(total_segments),
        _mp_key("q") + q,
        _mp_key("f") + _mp_uint(flags),
        _mp_key("m") + _mp_bin(hashmap),
    )
    return b"\x8b" + b"".join(fields)


@dataclasses.dataclass(frozen=True)
class AdvCase:
    name: str
    raw: bytes
    expect_ret: int
    transfer_size: int = 0
    data_size: int = 0
    part_count: int = 0
    resource_hash: bytes = b""
    random_hash: bytes = b""
    hashmap: bytes = b""
    null_raw: bool = False
    null_out: bool = False


HASH_A = _bytes_from(0x10, HASH_SIZE)
HASH_B = _bytes_from(0x31, HASH_SIZE)
RANDOM = _bytes_from(0x70, RANDOM_HASH_SIZE)
MAP_ONE = _bytes_from(0x90, MAPHASH_SIZE)
MAP_MAX = _bytes_from(0x40, ADV_MAX_PARTS * MAPHASH_SIZE)

VALID_SHORT = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    hashmap=MAP_ONE,
)
VALID_MAX = _advertisement(
    transfer_size=ADV_MAX_PARTS * PART_MAX_LEN,
    data_size=ADV_MAX_PARTS * PART_MAX_LEN - 16,
    part_count=ADV_MAX_PARTS,
    resource_hash=HASH_B,
    random_hash=RANDOM,
    hashmap=MAP_MAX,
)

BAD_HASHMAP = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=2,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    hashmap=MAP_ONE,
)
BAD_FLAGS = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    flags=0x03,
    hashmap=MAP_ONE,
)
BAD_REQUEST = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    request_nil=False,
    hashmap=MAP_ONE,
)
BAD_SEGMENT = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    segment_index=2,
    total_segments=2,
    hashmap=MAP_ONE,
)
BAD_PARTS = _advertisement(
    transfer_size=(ADV_MAX_PARTS + 1) * PART_MAX_LEN,
    data_size=64,
    part_count=ADV_MAX_PARTS + 1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    hashmap=_bytes_from(0x20, (ADV_MAX_PARTS + 1) * MAPHASH_SIZE),
)
BAD_TRANSFER_SMALL = _advertisement(
    transfer_size=PART_MAX_LEN,
    data_size=64,
    part_count=2,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    hashmap=_bytes_from(0x20, 2 * MAPHASH_SIZE),
)
BAD_DATA_GT_TRANSFER = _advertisement(
    transfer_size=64,
    data_size=65,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    hashmap=MAP_ONE,
)
BAD_ORIGINAL_HASH = _advertisement(
    transfer_size=128,
    data_size=96,
    part_count=1,
    resource_hash=HASH_A,
    random_hash=RANDOM,
    original_hash=HASH_B,
    hashmap=MAP_ONE,
)
BAD_H_LEN = VALID_SHORT.replace(_mp_bin(HASH_A), _mp_bin(HASH_A[:-1]), 1)
BAD_KEY_ORDER = b"\x8b" + (_mp_key("d") + _mp_uint(96)) + VALID_SHORT[3 + 2:]
BAD_EXTRA = VALID_SHORT + b"\x00"
BAD_RAW_TOO_LONG = VALID_SHORT + bytes(ADV_MAX_RAW_LEN - len(VALID_SHORT) + 1)

ADV_CASES = (
    AdvCase("short", VALID_SHORT, 0, 128, 96, 1, HASH_A, RANDOM, MAP_ONE),
    AdvCase(
        "max-hashmap",
        VALID_MAX,
        0,
        ADV_MAX_PARTS * PART_MAX_LEN,
        ADV_MAX_PARTS * PART_MAX_LEN - 16,
        ADV_MAX_PARTS,
        HASH_B,
        RANDOM,
        MAP_MAX,
    ),
    AdvCase("hashmap-mismatch", BAD_HASHMAP, -1),
    AdvCase("unsupported-flags", BAD_FLAGS, -1),
    AdvCase("request-id-present", BAD_REQUEST, -1),
    AdvCase("split-segment", BAD_SEGMENT, -1),
    AdvCase("too-many-parts", BAD_PARTS, -1),
    AdvCase("transfer-too-small", BAD_TRANSFER_SMALL, -1),
    AdvCase("data-gt-transfer", BAD_DATA_GT_TRANSFER, -1),
    AdvCase("original-hash-mismatch", BAD_ORIGINAL_HASH, -1),
    AdvCase("hash-length", BAD_H_LEN, -1),
    AdvCase("key-order", BAD_KEY_ORDER, -1),
    AdvCase("extra-byte", BAD_EXTRA, -1),
    AdvCase("raw-too-long", BAD_RAW_TOO_LONG, -1),
    AdvCase("null-raw", VALID_SHORT, -1, null_raw=True),
    AdvCase("null-out", VALID_SHORT, -1, null_out=True),
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


def _harness_asm(case: AdvCase) -> str:
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
        call    resource_advertisement_parse
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, parsed
        li      a1, {ADV_T_SIZE}
        call    .Lemit_bytes
        li      a0, 58
        call    .Lputc
        la      t1, parsed
        lw      a0, 100(t1)
        lw      a1, 96(t1)
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
        .skip   {ADV_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "resource_advertisement_parse_harness.S"
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

    elf = tmp_path / "resource_advertisement_parse.elf"
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
            out.extend(emu.read(4096, timeout=0.5))
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


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "resource_advertisement_parse") > 0


@pytest.mark.parametrize("case", ADV_CASES, ids=[c.name for c in ADV_CASES])
def test_resource_advertisement_parse_qemu(tmp_path: Path, case: AdvCase) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _harness_asm(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert outputs == []
        return

    parsed, hashmap = outputs
    assert _u32le(parsed, ADV_OFF_RAW_LEN) == len(case.raw)
    assert _u32le(parsed, ADV_OFF_TRANSFER_SIZE) == case.transfer_size
    assert _u32le(parsed, ADV_OFF_DATA_SIZE) == case.data_size
    assert _u32le(parsed, ADV_OFF_PART_COUNT) == case.part_count
    assert _u32le(parsed, ADV_OFF_FLAGS) == 1
    assert _u32le(parsed, ADV_OFF_SEGMENT_INDEX) == 1
    assert _u32le(parsed, ADV_OFF_TOTAL_SEGMENTS) == 1
    assert parsed[ADV_OFF_RESOURCE_HASH:ADV_OFF_RESOURCE_HASH + HASH_SIZE] == case.resource_hash
    assert parsed[ADV_OFF_RANDOM_HASH:ADV_OFF_RANDOM_HASH + RANDOM_HASH_SIZE] == case.random_hash
    assert parsed[ADV_OFF_ORIGINAL_HASH:ADV_OFF_ORIGINAL_HASH + HASH_SIZE] == case.resource_hash
    assert _u32le(parsed, ADV_OFF_HASHMAP_LEN) == len(case.hashmap)
    assert hashmap == case.hashmap
