"""Direct QEMU tests for milestone-7 resource plaintext dispatch."""

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
    "src/resource/resource_process_plaintext.S",
    "src/resource/channel_envelope_parse.S",
    "src/resource/resource_advertisement_parse.S",
    "src/resource/resource_reassembly_init.S",
    "src/resource/resource_reassembly_update.S",
    "src/resource/resource_part_parse.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/resource.S",
    "src/state/sha256.S",
)

CTX_RESOURCE = 0x01
CTX_RESOURCE_ADV = 0x02
CTX_CHANNEL = 0x0E

RESOURCE_ERR_INVAL = -1
RESOURCE_REASM_RESULT_ADVERTISED = 1
RESOURCE_REASM_RESULT_PART_ACCEPTED = 2
RESOURCE_REASM_RESULT_DUPLICATE = 3
RESOURCE_REASM_RESULT_COMPLETE = 4
RESOURCE_PROCESS_STATUS_CHANNEL = 5

REASM_ENTRY_SIZE = 316
REASM_TABLE_SIZE = 632
REASM_OFF_STATUS = 1
REASM_OFF_RECEIVED_COUNT = 8
REASM_OFF_CONSECUTIVE_IDX = 12
REASM_STATUS_COMPLETE = 2

HASH_SIZE = 32
RANDOM_HASH_SIZE = 4
MAPHASH_SIZE = 4


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 17) & 0xFF for i in range(length))


def _maphash(payload: bytes, random_hash: bytes) -> bytes:
    return hashlib.sha256(payload + random_hash).digest()[:MAPHASH_SIZE]


def _envelope(msgtype: int, sequence: int, payload: bytes) -> bytes:
    return (
        msgtype.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + len(payload).to_bytes(2, "big")
        + payload
    )


def _mp_key(ch: str) -> bytes:
    return b"\xa1" + ch.encode("ascii")


def _mp_uint(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + bytes([value])
    if value <= 0xFFFF:
        return b"\xcd" + value.to_bytes(2, "big")
    return b"\xce" + value.to_bytes(4, "big")


def _mp_bin(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"\xc4" + bytes([len(data)]) + data
    return b"\xc5" + len(data).to_bytes(2, "big") + data


def _advertisement(resource_hash: bytes, random_hash: bytes, parts: tuple[bytes, ...]) -> bytes:
    hashmap = b"".join(_maphash(part, random_hash) for part in parts)
    transfer_size = 1 if len(parts) == 1 else (len(parts) - 1) * 431 + 1
    return b"\x8b" + b"".join(
        (
            _mp_key("t") + _mp_uint(transfer_size),
            _mp_key("d") + _mp_uint(transfer_size),
            _mp_key("n") + _mp_uint(len(parts)),
            _mp_key("h") + _mp_bin(resource_hash),
            _mp_key("r") + _mp_bin(random_hash),
            _mp_key("o") + _mp_bin(resource_hash),
            _mp_key("i") + _mp_uint(1),
            _mp_key("l") + _mp_uint(1),
            _mp_key("q") + b"\xc0",
            _mp_key("f") + _mp_uint(1),
            _mp_key("m") + _mp_bin(hashmap),
        )
    )


RESOURCE_HASH = _bytes_from(0x20, HASH_SIZE)
RANDOM_HASH = b"RND0"
PARTS = (b"first-resource-part", b"second-resource-part")
ADV_RAW = _advertisement(RESOURCE_HASH, RANDOM_HASH, PARTS)
CHANNEL_RAW = _envelope(0x1234, 7, b"channel")
BAD_CHANNEL_RAW = CHANNEL_RAW[:-1]


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    body: str
    line_count: int
    expected: tuple[int, ...]


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
.Lemit_hex32_line:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        call    .Lemit_hex32
        call    .Lnewline
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

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

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 4f
        addi    a0, a0, 87
        ret
4:      addi    a0, a0, 48
        ret

.Lnewline:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lputc:
        li      t0, 0x10000000
5:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 5b
        sb      a0, 0(t0)
        ret
"""


def _call(context: int, label: str, length: int, *, null_link: bool = False) -> str:
    link_arg = "mv      a0, zero" if null_link else "la      a0, link_entry"
    return f"""
        {link_arg}
        li      a1, {context}
        la      a2, {label}
        li      a3, {length}
        call    resource_process_plaintext
        call    .Lemit_hex32_line
"""


def _harness_asm(body: str) -> str:
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

{body}

.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}

        .section .rodata.input, "a", @progbits
channel_raw:
        .byte   {_byte_list(CHANNEL_RAW)}
bad_channel_raw:
        .byte   {_byte_list(BAD_CHANNEL_RAW)}
adv_raw:
        .byte   {_byte_list(ADV_RAW)}
part0:
        .byte   {_byte_list(PARTS[0])}
part1:
        .byte   {_byte_list(PARTS[1])}

        .section .bss.link_entry, "aw", @nobits
        .balign 4
link_entry:
        .skip   16
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "resource_process_plaintext_harness.S"
    harness.write_text(_harness_asm(body), encoding="utf-8")

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

    elf = tmp_path / "resource_process_plaintext.elf"
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


def _run_qemu(tmp_path: Path, body: str, line_count: int) -> list[bytes]:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, body))
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(120):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break
    return bytes(out).splitlines()[:line_count]


def _parse_ret(line: bytes) -> int:
    ret_u32 = int(line, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


SCENARIOS = (
    Scenario(
        "channel",
        _call(CTX_CHANNEL, "channel_raw", len(CHANNEL_RAW)),
        1,
        (RESOURCE_PROCESS_STATUS_CHANNEL,),
    ),
    Scenario(
        "bad-channel",
        _call(CTX_CHANNEL, "bad_channel_raw", len(BAD_CHANNEL_RAW)),
        1,
        (RESOURCE_ERR_INVAL,),
    ),
    Scenario(
        "resource-transfer",
        "        call    resource_reassembly_init\n"
        + _call(CTX_RESOURCE_ADV, "adv_raw", len(ADV_RAW))
        + _call(CTX_RESOURCE, "part0", len(PARTS[0]))
        + _call(CTX_RESOURCE, "part0", len(PARTS[0]))
        + _call(CTX_RESOURCE, "part1", len(PARTS[1])),
        4,
        (
            RESOURCE_REASM_RESULT_ADVERTISED,
            RESOURCE_REASM_RESULT_PART_ACCEPTED,
            RESOURCE_REASM_RESULT_DUPLICATE,
            RESOURCE_REASM_RESULT_COMPLETE,
        ),
    ),
    Scenario(
        "unknown-context",
        _call(0x7E, "channel_raw", len(CHANNEL_RAW)),
        1,
        (RESOURCE_ERR_INVAL,),
    ),
    Scenario(
        "null-link",
        _call(CTX_CHANNEL, "channel_raw", len(CHANNEL_RAW), null_link=True),
        1,
        (RESOURCE_ERR_INVAL,),
    ),
)


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "resource_process_plaintext") > 0


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_resource_process_plaintext_qemu(tmp_path: Path, scenario: Scenario) -> None:
    lines = _run_qemu(tmp_path, scenario.body, scenario.line_count)
    assert tuple(_parse_ret(line) for line in lines) == scenario.expected
