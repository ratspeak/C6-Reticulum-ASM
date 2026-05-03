"""Direct QEMU tests for the milestone-4 qemu flash model."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/flash/flash_init.S",
    "src/flash/flash_read.S",
    "src/flash/flash_write_page.S",
    "src/flash/flash_erase_sector.S",
    "src/state/flash.S",
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
    return ", ".join(f"0x{b:02x}" for b in data)


def _harness_asm(body: str, data: bytes = b"", data2: bytes = b"") -> str:
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

        .section .rodata.test_data, "a"
        .balign 4
data:
        .byte   {_byte_list(data)}
data2:
        .byte   {_byte_list(data2)}

        .section .bss.out_buf, "aw", @nobits
        .balign 4
out_buf:
        .skip   512
"""


def _build_test_elf(
    tmp_path: Path, body: str, data: bytes = b"", data2: bytes = b"",
) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "flash_harness.S"
    harness.write_text(_harness_asm(body, data, data2), encoding="utf-8")

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

    elf = tmp_path / "flash_harness.elf"
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
        for _ in range(120):
            out.extend(emu.read(1024, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break
    return bytes(out)


def _parse_lines(output: bytes) -> list[tuple[int, bytes]]:
    parsed: list[tuple[int, bytes]] = []
    for line in output.splitlines():
        ret_hex, sep, data_hex = line.partition(b":")
        assert sep == b":", output
        ret_u32 = int(ret_hex, 16)
        ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
        data = bytes.fromhex(data_hex.decode()) if data_hex else b""
        parsed.append((ret, data))
    return parsed


def _run_case(
    tmp_path: Path,
    body: str,
    *,
    line_count: int,
    data: bytes = b"",
    data2: bytes = b"",
) -> list[tuple[int, bytes]]:
    elf = _build_test_elf(tmp_path, body, data, data2)
    return _parse_lines(_run_qemu(elf, line_count))


def test_flash_symbols_present_in_direct_elf(tmp_path: Path) -> None:
    elf = _build_test_elf(tmp_path, "", b"", b"")
    for name in (
        "flash_init",
        "flash_read",
        "flash_write_page",
        "flash_erase_sector",
        "flash_model_region",
    ):
        assert build.symbol_address(elf, name) > 0


def test_init_erases_and_init_is_once(tmp_path: Path) -> None:
    body = """
        call    flash_init
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 0
        la      a1, out_buf
        li      a2, 16
        call    flash_read
        la      a1, out_buf
        li      a2, 16
        call    .Lemit_result

        li      a0, 0
        la      a1, data
        li      a2, 1
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        call    flash_init
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 0
        la      a1, out_buf
        li      a2, 1
        call    flash_read
        la      a1, out_buf
        li      a2, 1
        call    .Lemit_result
    """
    lines = _run_case(tmp_path, body, line_count=5, data=b"\x00")
    assert lines == [
        (0, b""),
        (0, b"\xff" * 16),
        (0, b""),
        (0, b""),
        (0, b"\x00"),
    ]


def test_write_round_trip_then_erase(tmp_path: Path) -> None:
    data = bytes(range(1, 9))
    body = """
        call    flash_init

        li      a0, 32
        la      a1, data
        li      a2, 8
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 32
        la      a1, out_buf
        li      a2, 8
        call    flash_read
        la      a1, out_buf
        li      a2, 8
        call    .Lemit_result

        li      a0, 0
        call    flash_erase_sector
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 32
        la      a1, out_buf
        li      a2, 8
        call    flash_read
        la      a1, out_buf
        li      a2, 8
        call    .Lemit_result
    """
    lines = _run_case(tmp_path, body, line_count=4, data=data)
    assert lines == [
        (0, b""),
        (0, data),
        (0, b""),
        (0, b"\xff" * 8),
    ]


def test_cross_page_write_fails_without_mutation(tmp_path: Path) -> None:
    seed = b"\x0f\xf0\x55\xaa\x00\x11\x22\x33"
    replacement = b"\x00" * 8
    body = """
        call    flash_init

        li      a0, 248
        la      a1, data
        li      a2, 8
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 250
        la      a1, data2
        li      a2, 8
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 248
        la      a1, out_buf
        li      a2, 8
        call    flash_read
        la      a1, out_buf
        li      a2, 8
        call    .Lemit_result
    """
    lines = _run_case(
        tmp_path, body, line_count=3, data=seed, data2=replacement,
    )
    assert lines == [
        (0, b""),
        (-1, b""),
        (0, seed),
    ]


def test_zero_to_one_write_fails_without_mutation(tmp_path: Path) -> None:
    body = """
        call    flash_init

        li      a0, 64
        la      a1, data
        li      a2, 1
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 64
        la      a1, data2
        li      a2, 1
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 64
        la      a1, out_buf
        li      a2, 1
        call    flash_read
        la      a1, out_buf
        li      a2, 1
        call    .Lemit_result
    """
    lines = _run_case(tmp_path, body, line_count=3, data=b"\x00", data2=b"\xff")
    assert lines == [
        (0, b""),
        (-1, b""),
        (0, b"\x00"),
    ]


def test_bounds_zero_length_and_alignment_rejections(tmp_path: Path) -> None:
    body = """
        call    flash_init

        li      a0, 4096
        mv      a1, zero
        mv      a2, zero
        call    flash_read
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 4095
        la      a1, out_buf
        li      a2, 2
        call    flash_read
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 4096
        la      a1, data
        li      a2, 1
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 0
        la      a1, data
        mv      a2, zero
        call    flash_write_page
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result

        li      a0, 1
        call    flash_erase_sector
        mv      a1, zero
        mv      a2, zero
        call    .Lemit_result
    """
    lines = _run_case(tmp_path, body, line_count=5, data=b"\x00")
    assert lines == [
        (0, b""),
        (-1, b""),
        (-1, b""),
        (-1, b""),
        (-1, b""),
    ]
