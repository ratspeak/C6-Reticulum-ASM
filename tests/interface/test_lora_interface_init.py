"""Direct QEMU tests for the Reticulum LoRa interface initializer."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/interface/lora/lora_interface_init.S",
    "src/interface/lora/sx1262_init.S",
    "src/interface/lora/sx1262_reset.S",
    "src/interface/lora/sx1262_command_write.S",
    "src/interface/lora/sx1262_command_read.S",
    "src/interface/spi/spi_init.S",
    "src/interface/spi/spi_transfer.S",
    "src/interface/gpio/gpio_config_output.S",
    "src/interface/gpio/gpio_config_input.S",
    "src/interface/gpio/gpio_write.S",
    "src/interface/gpio/gpio_read.S",
    "src/clock/clock_delay_us.S",
    "src/state/gpio.S",
    "src/state/spi.S",
    "src/state/lora.S",
)

LORA_OK = 0
LORA_ERR_BUSY_TIMEOUT = 0xFFFFFFFE
GPIO_BUSY_MASK = 1 << 6


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} not on PATH")
    return path


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"{' '.join(cmd)} failed with exit {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )


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

        la      t0, gpio_model_configured
        sw      zero, 0(t0)
        la      t0, gpio_model_direction
        sw      zero, 0(t0)
        la      t0, gpio_model_level
        sw      zero, 0(t0)
        la      t0, spi_model_initialized
        sw      zero, 0(t0)
        la      t0, spi_model_last_status
        sw      zero, 0(t0)
        la      t0, spi_model_transfer_count
        sw      zero, 0(t0)
        la      t0, spi_model_tx_log_len
        sw      zero, 0(t0)
        la      t0, spi_model_force_timeout
        sw      zero, 0(t0)
        la      t0, sx1262_model_initialized
        sw      zero, 0(t0)
        la      t0, sx1262_model_init_error
        sw      zero, 0(t0)
        la      t0, sx1262_model_status_byte
        sw      zero, 0(t0)
        la      t0, sx1262_model_tx_len
        sw      zero, 0(t0)
        la      t0, sx1262_model_last_irq
        sw      zero, 0(t0)
        la      t0, sx1262_model_rx_len
        sw      zero, 0(t0)
        la      t0, lora_interface_initialized
        sw      zero, 0(t0)
        la      t0, lora_interface_last_status
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
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")
    harness = tmp_path / "lora_interface_init_harness.S"
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

    elf = tmp_path / "lora_interface_init_harness.elf"
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


def _run_body(tmp_path: Path, body: str, line_count: int) -> list[int]:
    return _run_qemu(_build_test_elf(tmp_path, body), line_count)


def _call(symbol: str, *args: int) -> str:
    setup = "\n".join(f"        li      a{idx}, {value}" for idx, value in enumerate(args))
    return f"""
{setup}
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


def test_lora_interface_init_sets_ready_state(tmp_path: Path) -> None:
    body = (
        _store_word("spi_model_rx_source", 0x00005A00)
        + _call("lora_interface_init", 100)
        + _load_word("lora_interface_initialized")
        + _load_word("lora_interface_last_status")
        + _load_word("sx1262_model_initialized")
        + _load_word("sx1262_model_status_byte")
        + _load_word("sx1262_model_init_error")
        + _load_word("spi_model_transfer_count")
    )
    assert _run_body(tmp_path, body, 7) == [
        LORA_OK,
        1,
        LORA_OK,
        1,
        0x5A,
        LORA_OK,
        15,
    ]


def test_lora_interface_init_zero_timeout_uses_default(tmp_path: Path) -> None:
    body = (
        _store_word("spi_model_rx_source", 0x00003300)
        + _call("lora_interface_init", 0)
        + _load_word("lora_interface_initialized")
        + _load_word("sx1262_model_status_byte")
    )
    assert _run_body(tmp_path, body, 3) == [
        LORA_OK,
        1,
        0x33,
    ]


def test_lora_interface_init_records_error_and_stays_not_ready(tmp_path: Path) -> None:
    body = (
        _store_word("gpio_model_level", GPIO_BUSY_MASK)
        + _call("lora_interface_init", 2)
        + _load_word("lora_interface_initialized")
        + _load_word("lora_interface_last_status")
        + _load_word("sx1262_model_initialized")
        + _load_word("sx1262_model_init_error")
        + _load_word("spi_model_transfer_count")
    )
    assert _run_body(tmp_path, body, 6) == [
        LORA_ERR_BUSY_TIMEOUT,
        0,
        LORA_ERR_BUSY_TIMEOUT,
        0,
        LORA_ERR_BUSY_TIMEOUT,
        0,
    ]
