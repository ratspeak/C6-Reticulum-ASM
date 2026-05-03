"""Direct QEMU tests for milestone-7 resource reassembly update."""

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

RESOURCE_OK = 0
RESOURCE_ERR_INVAL = -1
RESOURCE_REASM_RESULT_ADVERTISED = 1
RESOURCE_REASM_RESULT_PART_ACCEPTED = 2
RESOURCE_REASM_RESULT_DUPLICATE = 3
RESOURCE_REASM_RESULT_COMPLETE = 4

HASH_SIZE = 32
RANDOM_HASH_SIZE = 4
MAPHASH_SIZE = 4
REASM_ENTRY_SIZE = 316
REASM_TABLE_SIZE = 632
REASM_CAPACITY = 2

REASM_OFF_VALID = 0
REASM_OFF_STATUS = 1
REASM_OFF_WINDOW = 2
REASM_OFF_TOTAL_PARTS = 4
REASM_OFF_RECEIVED_COUNT = 8
REASM_OFF_CONSECUTIVE_IDX = 12
REASM_OFF_RESOURCE_HASH = 16
REASM_OFF_RANDOM_HASH = 48
REASM_OFF_RECEIVED_BITMAP = 52
REASM_OFF_HASHMAP = 60

REASM_STATUS_RECEIVING = 1
REASM_STATUS_COMPLETE = 2


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 19) & 0xFF for i in range(length))


def _maphash(payload: bytes, random_hash: bytes) -> bytes:
    return hashlib.sha256(payload + random_hash).digest()[:MAPHASH_SIZE]


@dataclasses.dataclass(frozen=True)
class ResourceFixture:
    name: str
    resource_hash: bytes
    random_hash: bytes
    parts: tuple[bytes, ...]

    @property
    def hashmap(self) -> bytes:
        return b"".join(_maphash(part, self.random_hash) for part in self.parts)

    @property
    def transfer_size(self) -> int:
        return sum(len(part) for part in self.parts)


RES_A = ResourceFixture(
    "a",
    _bytes_from(0x10, HASH_SIZE),
    b"RND0",
    (b"part-zero", b"part-one", b"part-two"),
)
RES_B = ResourceFixture(
    "b",
    _bytes_from(0x70, HASH_SIZE),
    b"RND1",
    (b"b-zero", b"b-one"),
)
UNKNOWN_PART = b"not-in-map"


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

.Lemit_ret_table:
        addi    sp, sp, -16
        sw      s0, 0(sp)
        sw      ra, 12(sp)
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        la      a0, resource_reassembly_table
        li      a1, REASM_TABLE_SIZE
        call    .Lemit_bytes
        call    .Lnewline
        lw      s0, 0(sp)
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


def _resource_data() -> str:
    blocks: list[str] = []
    for res in (RES_A, RES_B):
        blocks.append(f"""
        .balign 4
hashmap_{res.name}:
        .byte   {_byte_list(res.hashmap)}
        .balign 4
adv_{res.name}:
        .word   0
        .word   {res.transfer_size}
        .word   {res.transfer_size}
        .word   {len(res.parts)}
        .word   1
        .word   1
        .word   1
        .byte   {_byte_list(res.resource_hash)}
        .byte   {_byte_list(res.random_hash)}
        .byte   {_byte_list(res.resource_hash)}
        .word   {len(res.hashmap)}
        .word   hashmap_{res.name}
""")
        for idx, part in enumerate(res.parts):
            blocks.append(f"""
part_{res.name}_{idx}:
        .byte   {_byte_list(part)}
""")
    blocks.append(f"""
unknown_part:
        .byte   {_byte_list(UNKNOWN_PART)}
""")
    return "\n".join(blocks)


def _harness_asm(body: str) -> str:
    return f"""
        .equ REASM_TABLE_SIZE, {REASM_TABLE_SIZE}

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
{_resource_data()}
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "resource_reassembly_update_harness.S"
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

    elf = tmp_path / "resource_reassembly_update.elf"
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
            out.extend(emu.read(4096, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break
    return bytes(out).splitlines()[:line_count]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def _parse_line(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, table_hex = line.partition(b":")
    return _parse_ret(ret_hex), bytes.fromhex(table_hex.decode())


def _u32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _entry(table: bytes, index: int = 0) -> bytes:
    start = index * REASM_ENTRY_SIZE
    return table[start:start + REASM_ENTRY_SIZE]


def _advertise(label: str) -> str:
    return f"""
        la      a0, adv_{label}
        mv      a1, zero
        mv      a2, zero
        call    resource_reassembly_update
"""


def _part(label: str, idx: int) -> str:
    part = (RES_A if label == "a" else RES_B).parts[idx]
    return f"""
        mv      a0, zero
        la      a1, part_{label}_{idx}
        li      a2, {len(part)}
        call    resource_reassembly_update
"""


def _emit() -> str:
    return "        call    .Lemit_ret_table\n"


def test_symbols_exist(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "resource_reassembly_update") > 0
    assert build.symbol_address(artifacts.elf, "resource_reassembly_table") > 0


def test_advertisement_installs_receive_entry(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("a")}
{_emit()}
"""
    ret, table = _parse_line(_run_qemu(tmp_path, body, 1)[0])
    entry = _entry(table)
    assert ret == RESOURCE_REASM_RESULT_ADVERTISED
    assert entry[REASM_OFF_VALID] == 1
    assert entry[REASM_OFF_STATUS] == REASM_STATUS_RECEIVING
    assert entry[REASM_OFF_WINDOW] == 4
    assert _u32le(entry, REASM_OFF_TOTAL_PARTS) == len(RES_A.parts)
    assert _u32le(entry, REASM_OFF_RECEIVED_COUNT) == 0
    assert _u32le(entry, REASM_OFF_CONSECUTIVE_IDX) == 0
    assert entry[REASM_OFF_RESOURCE_HASH:REASM_OFF_RESOURCE_HASH + HASH_SIZE] == RES_A.resource_hash
    assert entry[REASM_OFF_RANDOM_HASH:REASM_OFF_RANDOM_HASH + RANDOM_HASH_SIZE] == RES_A.random_hash
    assert entry[REASM_OFF_RECEIVED_BITMAP:REASM_OFF_RECEIVED_BITMAP + 8] == bytes(8)
    assert entry[REASM_OFF_HASHMAP:REASM_OFF_HASHMAP + len(RES_A.hashmap)] == RES_A.hashmap


def test_out_of_order_parts_advance_consecutive_index(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("a")}
{_part("a", 1)}
{_emit()}
{_part("a", 0)}
{_emit()}
"""
    lines = _run_qemu(tmp_path, body, 2)
    ret1, table1 = _parse_line(lines[0])
    ret2, table2 = _parse_line(lines[1])
    entry1 = _entry(table1)
    entry2 = _entry(table2)

    assert ret1 == RESOURCE_REASM_RESULT_PART_ACCEPTED
    assert _u32le(entry1, REASM_OFF_RECEIVED_COUNT) == 1
    assert _u32le(entry1, REASM_OFF_CONSECUTIVE_IDX) == 0
    assert entry1[REASM_OFF_RECEIVED_BITMAP] == 0b00000010

    assert ret2 == RESOURCE_REASM_RESULT_PART_ACCEPTED
    assert _u32le(entry2, REASM_OFF_RECEIVED_COUNT) == 2
    assert _u32le(entry2, REASM_OFF_CONSECUTIVE_IDX) == 2
    assert entry2[REASM_OFF_RECEIVED_BITMAP] == 0b00000011


def test_duplicate_part_does_not_increment_count(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("a")}
{_part("a", 0)}
{_part("a", 0)}
{_emit()}
"""
    ret, table = _parse_line(_run_qemu(tmp_path, body, 1)[0])
    entry = _entry(table)
    assert ret == RESOURCE_REASM_RESULT_DUPLICATE
    assert _u32le(entry, REASM_OFF_RECEIVED_COUNT) == 1
    assert entry[REASM_OFF_RECEIVED_BITMAP] == 0b00000001


def test_complete_marks_entry_complete(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("b")}
{_part("b", 0)}
{_part("b", 1)}
{_emit()}
"""
    ret, table = _parse_line(_run_qemu(tmp_path, body, 1)[0])
    entry = _entry(table)
    assert ret == RESOURCE_REASM_RESULT_COMPLETE
    assert entry[REASM_OFF_STATUS] == REASM_STATUS_COMPLETE
    assert _u32le(entry, REASM_OFF_RECEIVED_COUNT) == len(RES_B.parts)
    assert _u32le(entry, REASM_OFF_CONSECUTIVE_IDX) == len(RES_B.parts)


def test_unknown_part_rejects_without_state_change(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("a")}
        mv      a0, zero
        la      a1, unknown_part
        li      a2, {len(UNKNOWN_PART)}
        call    resource_reassembly_update
{_emit()}
"""
    ret, table = _parse_line(_run_qemu(tmp_path, body, 1)[0])
    entry = _entry(table)
    assert ret == RESOURCE_ERR_INVAL
    assert _u32le(entry, REASM_OFF_RECEIVED_COUNT) == 0
    assert entry[REASM_OFF_RECEIVED_BITMAP:REASM_OFF_RECEIVED_BITMAP + 8] == bytes(8)


def test_duplicate_advertisement_preserves_existing_progress(tmp_path: Path) -> None:
    body = f"""
        call    resource_reassembly_init
{_advertise("a")}
{_part("a", 0)}
{_advertise("a")}
{_emit()}
"""
    ret, table = _parse_line(_run_qemu(tmp_path, body, 1)[0])
    entry = _entry(table)
    assert ret == RESOURCE_REASM_RESULT_DUPLICATE
    assert _u32le(entry, REASM_OFF_RECEIVED_COUNT) == 1
    assert entry[REASM_OFF_RECEIVED_BITMAP] == 0b00000001
