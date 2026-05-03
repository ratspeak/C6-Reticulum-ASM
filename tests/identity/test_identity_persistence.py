"""Direct QEMU tests for milestone-4 identity_save / identity_load."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/identity/identity_save.S",
    "src/identity/identity_load.S",
    "src/identity/identity_hash.S",
    "src/flash/flash_init.S",
    "src/flash/flash_read.S",
    "src/flash/flash_write_page.S",
    "src/flash/flash_erase_sector.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/identity.S",
    "src/state/flash.S",
    "src/state/sha256.S",
)

IDENTITY_T_SIZE = 160
RECORD_SIZE = 256
IDENTITY_ERR_MISSING = -2


def _identity_bytes() -> bytes:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes((i * 11 + 5) & 0xFF for i in range(32))
    material = oracle.identity_from_private_parts(xsk, esk)
    return material.private_key + material.public_key + material.hash + bytes(16)


VALID_IDENTITY = _identity_bytes()


def _record(identity: bytes) -> bytes:
    assert len(identity) == IDENTITY_T_SIZE
    out = bytearray([0xFF] * RECORD_SIZE)
    out[0:4] = b"RID1"
    out[4] = 1
    out[5] = 0
    out[6:8] = (48).to_bytes(2, "little")
    out[8:12] = IDENTITY_T_SIZE.to_bytes(4, "little")
    out[12:16] = bytes(4)
    out[48:208] = identity
    out[16:48] = hashlib.sha256(bytes(out[0:16]) + identity).digest()
    return bytes(out)


VALID_RECORD = _record(VALID_IDENTITY)


def _corrupt(offset: int, value: int) -> bytes:
    out = bytearray(VALID_RECORD)
    out[offset] = value
    return bytes(out)


CORRUPT_RECORDS = (
    pytest.param(_corrupt(0, 0x00), id="bad_magic"),
    pytest.param(_corrupt(4, 0x02), id="bad_version"),
    pytest.param(_corrupt(5, 0x01), id="bad_flags"),
    pytest.param(_corrupt(6, 0x31), id="bad_header_len"),
    pytest.param(_corrupt(8, 0x9F), id="bad_identity_len"),
    pytest.param(_corrupt(16, VALID_RECORD[16] ^ 0x01), id="bad_checksum"),
    pytest.param(_corrupt(48 + 128, VALID_RECORD[48 + 128] ^ 0x01), id="bad_hash"),
    pytest.param(_corrupt(208, 0x00), id="bad_padding"),
)


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


def _harness_asm(body: str, identity: bytes = VALID_IDENTITY, record: bytes = VALID_RECORD) -> str:
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

.Lemit_result:
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

        .size   _reset, . - _reset

        .section .rodata.identity_data, "a"
        .balign 4
identity_data:
        .byte   {_byte_list(identity)}
record_data:
        .byte   {_byte_list(record)}

        .section .bss.test_buffers, "aw", @nobits
        .balign 16
identity_out:
        .skip   160
record_out:
        .skip   256
"""


def _build_test_elf(
    tmp_path: Path,
    body: str,
    *,
    identity: bytes = VALID_IDENTITY,
    record: bytes = VALID_RECORD,
) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "identity_persistence_harness.S"
    harness.write_text(_harness_asm(body, identity, record), encoding="utf-8")

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

    elf = tmp_path / "identity_persistence.elf"
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


def _run_qemu(elf: Path, line_count: int) -> bytes:
    cfg = target.TargetConfig(binary=elf)
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(160):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break
    return bytes(out)


def _parse_lines(output: bytes) -> list[tuple[int, bytes]]:
    parsed: list[tuple[int, bytes]] = []
    for line in output.splitlines():
        ret_hex, sep, data_hex = line.partition(b":")
        assert sep == b":", output
        ret_u32 = int(ret_hex, 16)
        ret = ret_u32 - (1 << 32) if ret_u32 & (1 << 31) else ret_u32
        data = bytes.fromhex(data_hex.decode()) if data_hex else b""
        parsed.append((ret, data))
    return parsed


def _run_case(tmp_path: Path, body: str, *, line_count: int, **kwargs) -> list[tuple[int, bytes]]:
    elf = _build_test_elf(tmp_path, body, **kwargs)
    return _parse_lines(_run_qemu(elf, line_count))


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_symbols_present(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "identity_save") > 0
    assert build.symbol_address(artifacts.elf, "identity_load") > 0


def test_save_load_round_trip_and_record(tmp_path: Path) -> None:
    body = """
        call    flash_init

        la      a0, identity_data
        call    identity_save
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        la      a0, identity_out
        call    identity_load
        la      a1, identity_out
        li      a2, 160
        call    .Lemit_result

        li      a0, 0
        la      a1, record_out
        li      a2, 256
        call    flash_read
        la      a1, record_out
        li      a2, 256
        call    .Lemit_result
    """
    lines = _run_case(tmp_path, body, line_count=3)
    assert lines == [
        (0, b""),
        (0, VALID_IDENTITY),
        (0, VALID_RECORD),
    ]


def test_missing_identity_returns_missing(tmp_path: Path) -> None:
    body = """
        call    flash_init
        la      a0, identity_out
        call    identity_load
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result
    """
    assert _run_case(tmp_path, body, line_count=1) == [(IDENTITY_ERR_MISSING, b"")]


def test_save_rejects_bad_identity_hash_without_writing(tmp_path: Path) -> None:
    bad_identity = bytearray(VALID_IDENTITY)
    bad_identity[128] ^= 0x01
    body = """
        call    flash_init

        la      a0, identity_data
        call    identity_save
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 0
        la      a1, record_out
        li      a2, 16
        call    flash_read
        la      a1, record_out
        li      a2, 16
        call    .Lemit_result
    """
    lines = _run_case(
        tmp_path, body, line_count=2, identity=bytes(bad_identity),
    )
    assert lines == [(-1, b""), (0, b"\xff" * 16)]


def test_load_accepts_prebuilt_valid_record(tmp_path: Path) -> None:
    body = """
        call    flash_init
        li      a0, 0
        la      a1, record_data
        li      a2, 256
        call    flash_write_page

        la      a0, identity_out
        call    identity_load
        la      a1, identity_out
        li      a2, 160
        call    .Lemit_result
    """
    assert _run_case(tmp_path, body, line_count=1) == [(0, VALID_IDENTITY)]


@pytest.mark.parametrize("record", CORRUPT_RECORDS)
def test_load_rejects_malformed_records(tmp_path: Path, record: bytes) -> None:
    body = """
        call    flash_init
        li      a0, 0
        la      a1, record_data
        li      a2, 256
        call    flash_write_page

        la      a0, identity_out
        call    identity_load
        la      a1, identity_out
        li      a2, 16
        call    .Lemit_result
    """
    assert _run_case(tmp_path, body, line_count=1, record=record) == [(-1, bytes(16))]
