"""Direct QEMU tests for milestone-8 SPI helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/interface/spi/spi_init.S",
    "src/interface/spi/spi_transfer.S",
    "src/state/spi.S",
)

SPI_OK = 0
SPI_ERR_INVAL = -1
SPI_ERR_OVERFLOW = -2
SPI_ERR_TIMEOUT = -3
SPI_DEFAULT_HZ = 1_000_000


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


def _harness_asm(body: str, data: str = "") -> str:
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

        la      t0, spi_model_initialized
        sw      zero, 0(t0)
        la      t0, spi_model_clock_hz
        sw      zero, 0(t0)
        la      t0, spi_model_last_status
        sw      zero, 0(t0)
        la      t0, spi_model_transfer_count
        sw      zero, 0(t0)
        la      t0, spi_model_tx_log_len
        sw      zero, 0(t0)
        la      t0, spi_model_force_timeout
        sw      zero, 0(t0)

{body}

.Lhalt:
        wfi
        j       .Lhalt

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

        .size   _reset, . - _reset

{data}
"""


def _build_test_elf(tmp_path: Path, body: str, data: str = "") -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "spi_harness.S"
    harness.write_text(_harness_asm(body, data), encoding="utf-8")

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

    elf = tmp_path / "spi_harness.elf"
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


def _run_qemu(elf: Path, line_count: int) -> list[int]:
    cfg = target.TargetConfig(binary=elf)
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(120):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break

    lines = bytes(out).replace(b"\r", b"").splitlines()
    assert len(lines) >= line_count, bytes(out)
    return [int(line[:8], 16) for line in lines[:line_count]]


def _run_body(tmp_path: Path, body: str, line_count: int, data: str = "") -> list[int]:
    return _run_qemu(_build_test_elf(tmp_path, body, data), line_count)


def _call(symbol: str, *args: int | str) -> str:
    setup: list[str] = []
    for idx, value in enumerate(args):
        if isinstance(value, str):
            setup.append(f"        la      a{idx}, {value}")
        else:
            setup.append(f"        li      a{idx}, {value}")
    return f"""
{chr(10).join(setup)}
        call    {symbol}
        call    .Lemit_hex32_line
"""


def _load_word(symbol: str) -> str:
    return f"""
        la      t0, {symbol}
        lw      a0, 0(t0)
        call    .Lemit_hex32_line
"""


def _store_word(symbol: str, value: int) -> str:
    return f"""
        la      t0, {symbol}
        li      t1, {value:#x}
        sw      t1, 0(t0)
"""


TEST_DATA = """
        .section .data.spi_test, "aw", @progbits
        .balign 4
tx4:
        .byte   0x11, 0x22, 0x33, 0x44
rx4:
        .word   0
rx3:
        .word   0
"""


def test_spi_init_sets_model_state(tmp_path: Path) -> None:
    body = (
        _call("spi_init")
        + _load_word("spi_model_initialized")
        + _load_word("spi_model_clock_hz")
        + _load_word("spi_model_last_status")
    )
    assert _run_body(tmp_path, body, 4) == [
        SPI_OK,
        1,
        SPI_DEFAULT_HZ,
        SPI_OK,
    ]


def test_full_duplex_transfer_logs_tx_and_fills_rx(tmp_path: Path) -> None:
    body = (
        _call("spi_init")
        + _store_word("spi_model_rx_source", 0xDDCCBBAA)
        + _call("spi_transfer", "tx4", "rx4", 4, 100)
        + _load_word("spi_model_tx_log_len")
        + _load_word("spi_model_transfer_count")
        + _load_word("spi_model_tx_log")
        + _load_word("rx4")
    )
    assert _run_body(tmp_path, body, 6, TEST_DATA) == [
        SPI_OK,
        SPI_OK,
        4,
        1,
        0x44332211,
        0xDDCCBBAA,
    ]


def test_rx_only_transfer_clocks_zeroes_and_reads_source(tmp_path: Path) -> None:
    body = (
        _call("spi_init")
        + _store_word("spi_model_rx_source", 0x00CCBBAA)
        + _call("spi_transfer", 0, "rx3", 3, 100)
        + _load_word("spi_model_tx_log_len")
        + _load_word("spi_model_tx_log")
        + _load_word("rx3")
    )
    assert _run_body(tmp_path, body, 5, TEST_DATA) == [
        SPI_OK,
        SPI_OK,
        3,
        0,
        0x00CCBBAA,
    ]


def test_invalid_overflow_timeout_and_zero_length_paths(tmp_path: Path) -> None:
    body = (
        _call("spi_transfer", "tx4", "rx4", 1, 100)
        + _call("spi_init")
        + _call("spi_transfer", 0, 0, 1, 100)
        + _call("spi_transfer", "tx4", "rx4", 257, 100)
        + _call("spi_transfer", "tx4", "rx4", 1, 0)
        + _store_word("spi_model_force_timeout", 1)
        + _call("spi_transfer", "tx4", "rx4", 1, 100)
        + _call("spi_transfer", 0, 0, 0, 0)
        + _load_word("spi_model_last_status")
    )
    assert _run_body(tmp_path, body, 8, TEST_DATA) == [
        0xFFFFFFFF,
        SPI_OK,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0xFFFFFFFD,
        0xFFFFFFFD,
        SPI_OK,
        SPI_OK,
    ]
