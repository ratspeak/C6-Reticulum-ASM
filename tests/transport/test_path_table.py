"""Direct QEMU tests for the milestone-5 transport path table."""

from __future__ import annotations

import dataclasses
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/transport/transport_path_init.S",
    "src/transport/transport_path_update.S",
    "src/transport/transport_path_lookup.S",
    "src/identity/identity_hash.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/transport.S",
    "src/state/sha256.S",
)

ANNOUNCE_RX_T_SIZE = 180
ANN_RX_OFF_RAW_LEN = 0
ANN_RX_OFF_PAYLOAD_LEN = 4
ANN_RX_OFF_APP_DATA_LEN = 8
ANN_RX_OFF_DEST_HASH = 12
ANN_RX_OFF_PUBLIC_KEY = 28
ANNOUNCE_BASE_RAW_LEN = 167
ANNOUNCE_HEADER_LEN = 19

TP_VALID = 0
TP_INTERFACE = 1
TP_HOPS = 2
TP_RESERVED = 3
TP_LAST_SEEN = 4
TP_DEST_HASH = 8
TP_IDENTITY_HASH = 24
TP_PUBLIC_KEY = 40
TP_ENTRY_SIZE = 104
TP_CAPACITY = 8


@dataclasses.dataclass(frozen=True)
class Ann:
    dest_hash: bytes
    public_key: bytes
    parsed: bytes


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


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 29) & 0xFF for i in range(length))


def _ann(index: int, *, dest: bytes | None = None) -> Ann:
    dest_hash = dest or _bytes_from(0x10 + index * 7, 16)
    public_key = _bytes_from(0x40 + index * 11, 64)
    parsed = bytearray(ANNOUNCE_RX_T_SIZE)
    struct.pack_into("<I", parsed, ANN_RX_OFF_RAW_LEN, ANNOUNCE_BASE_RAW_LEN)
    struct.pack_into(
        "<I", parsed, ANN_RX_OFF_PAYLOAD_LEN, ANNOUNCE_BASE_RAW_LEN - ANNOUNCE_HEADER_LEN
    )
    struct.pack_into("<I", parsed, ANN_RX_OFF_APP_DATA_LEN, 0)
    parsed[ANN_RX_OFF_DEST_HASH:ANN_RX_OFF_DEST_HASH + 16] = dest_hash
    parsed[ANN_RX_OFF_PUBLIC_KEY:ANN_RX_OFF_PUBLIC_KEY + 64] = public_key
    return Ann(dest_hash=dest_hash, public_key=public_key, parsed=bytes(parsed))


ANNOUNCES = [_ann(i) for i in range(9)]
ANNOUNCES[8] = _ann(8)
ANN_UPDATE_SAME_DEST = _ann(9, dest=ANNOUNCES[0].dest_hash)


def _ann_label(index: int) -> str:
    return "ann_update_same_dest" if index == 9 else f"ann{index}"


def _update(index: int, interface_id: int = 1, hops: int = 0) -> str:
    return f"""
        la      a0, {_ann_label(index)}
        li      a1, {interface_id}
        li      a2, {hops}
        call    transport_path_update
"""


def _lookup(index: int) -> str:
    return f"""
        la      a0, {_ann_label(index)}
        addi    a0, a0, {ANN_RX_OFF_DEST_HASH}
        la      a1, out_entry
        call    transport_path_lookup
        la      a1, out_entry
        li      a2, {TP_ENTRY_SIZE}
        call    .Lemit_ret_bytes
"""


def _harness_asm(body: str) -> str:
    data = "\n".join(
        f"""
        .balign 4
ann{i}:
        .byte   {_byte_list(ann.parsed)}
"""
        for i, ann in enumerate(ANNOUNCES)
    )
    data += f"""
        .balign 4
ann_update_same_dest:
        .byte   {_byte_list(ANN_UPDATE_SAME_DEST.parsed)}
"""
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

.Lemit_ret_bytes:
        addi    sp, sp, -16
        sw      s0, 0(sp)
        sw      s1, 4(sp)
        sw      ra, 12(sp)
        mv      s0, a1
        mv      s1, a2
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        mv      a0, s0
        mv      a1, s1
        call    .Lemit_bytes
        call    .Lnewline
        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

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

.Lcount_valid:
        la      t0, transport_path_table
        li      t1, {TP_CAPACITY}
        li      a0, 0
4:      lbu     t2, 0(t0)
        beqz    t2, 5f
        addi    a0, a0, 1
5:      addi    t0, t0, {TP_ENTRY_SIZE}
        addi    t1, t1, -1
        bnez    t1, 4b
        ret

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 6f
        addi    a0, a0, 87
        ret
6:      addi    a0, a0, 48
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
7:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 7b
        sb      a0, 0(t0)
        ret

        .global clock_now_ms
        .type   clock_now_ms, @function
clock_now_ms:
        la      t0, fake_now
        lw      a0, 0(t0)
        addi    t1, a0, 10
        sw      t1, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .data.test_announces, "aw", @progbits
{data}
fake_now:
        .word   100

        .section .bss.out_entry, "aw", @nobits
        .balign 4
out_entry:
        .skip   {TP_ENTRY_SIZE}
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "transport_path_harness.S"
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

    elf = tmp_path / "transport_path.elf"
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
            if len(out.splitlines()) >= line_count:
                break
    return out.splitlines()


def _parse_ret_entry(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, entry_hex = line.partition(b":")
    ret_u32 = int(ret_hex, 16)
    ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
    return ret, bytes.fromhex(entry_hex.decode())


def _entry_fields(entry: bytes) -> dict[str, bytes | int]:
    return {
        "valid": entry[TP_VALID],
        "interface": entry[TP_INTERFACE],
        "hops": entry[TP_HOPS],
        "reserved": entry[TP_RESERVED],
        "last_seen": struct.unpack_from("<I", entry, TP_LAST_SEEN)[0],
        "dest_hash": entry[TP_DEST_HASH:TP_DEST_HASH + 16],
        "identity_hash": entry[TP_IDENTITY_HASH:TP_IDENTITY_HASH + 16],
        "public_key": entry[TP_PUBLIC_KEY:TP_PUBLIC_KEY + 64],
    }


def test_functions_exist(artifacts: build.BuildArtifacts) -> None:
    for name in ("transport_path_init", "transport_path_update", "transport_path_lookup"):
        assert build.symbol_address(artifacts.elf, name) > 0


def test_insert_and_lookup_path(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
{_update(0, hops=3)}
{_lookup(0)}
        call    .Lcount_valid
        call    .Lemit_hex32_line
"""
    lookup_line, count_line = _run_qemu(tmp_path, body, line_count=2)
    ret, entry = _parse_ret_entry(lookup_line)
    fields = _entry_fields(entry)

    assert ret == 0
    assert int(count_line, 16) == 1
    assert fields["valid"] == 1
    assert fields["interface"] == 1
    assert fields["hops"] == 3
    assert fields["reserved"] == 0
    assert fields["last_seen"] == 100
    assert fields["dest_hash"] == ANNOUNCES[0].dest_hash
    assert fields["identity_hash"] == oracle.identity_hash(ANNOUNCES[0].public_key)
    assert fields["public_key"] == ANNOUNCES[0].public_key


def test_update_existing_destination(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
{_update(0, hops=1)}
{_update(9, hops=5)}
{_lookup(0)}
        call    .Lcount_valid
        call    .Lemit_hex32_line
"""
    lookup_line, count_line = _run_qemu(tmp_path, body, line_count=2)
    ret, entry = _parse_ret_entry(lookup_line)
    fields = _entry_fields(entry)

    assert ret == 0
    assert int(count_line, 16) == 1
    assert fields["hops"] == 5
    assert fields["last_seen"] == 110
    assert fields["dest_hash"] == ANNOUNCES[0].dest_hash
    assert fields["identity_hash"] == oracle.identity_hash(ANN_UPDATE_SAME_DEST.public_key)
    assert fields["public_key"] == ANN_UPDATE_SAME_DEST.public_key


def test_full_table_evicts_oldest_entry(tmp_path: Path) -> None:
    updates = "".join(_update(i, hops=i) for i in range(TP_CAPACITY + 1))
    body = f"""
        call    transport_path_init
{updates}
{_lookup(0)}
{_lookup(8)}
        call    .Lcount_valid
        call    .Lemit_hex32_line
"""
    missing_line, inserted_line, count_line = _run_qemu(tmp_path, body, line_count=3)
    missing_ret, _missing_entry = _parse_ret_entry(missing_line)
    inserted_ret, inserted_entry = _parse_ret_entry(inserted_line)
    fields = _entry_fields(inserted_entry)

    assert missing_ret == -2
    assert inserted_ret == 0
    assert int(count_line, 16) == TP_CAPACITY
    assert fields["hops"] == 8
    assert fields["last_seen"] == 180
    assert fields["dest_hash"] == ANNOUNCES[8].dest_hash
    assert fields["public_key"] == ANNOUNCES[8].public_key


def test_init_clears_existing_entries(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
{_update(0)}
        call    transport_path_init
{_lookup(0)}
        call    .Lcount_valid
        call    .Lemit_hex32_line
"""
    lookup_line, count_line = _run_qemu(tmp_path, body, line_count=2)
    ret, _entry = _parse_ret_entry(lookup_line)
    assert ret == -2
    assert int(count_line, 16) == 0


def test_invalid_inputs_reject(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        mv      a0, zero
        li      a1, 1
        li      a2, 0
        call    transport_path_update
        call    .Lemit_hex32_line
        la      a0, ann0
        li      a1, 0
        li      a2, 0
        call    transport_path_update
        call    .Lemit_hex32_line
        mv      a0, zero
        la      a1, out_entry
        call    transport_path_lookup
        call    .Lemit_hex32_line
        la      a0, ann0
        addi    a0, a0, {ANN_RX_OFF_DEST_HASH}
        mv      a1, zero
        call    transport_path_lookup
        call    .Lemit_hex32_line
"""
    lines = _run_qemu(tmp_path, body, line_count=4)
    assert [int(line, 16) - (1 << 32) for line in lines] == [-1, -1, -1, -1]
