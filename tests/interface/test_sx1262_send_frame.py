"""Direct QEMU tests for SX1262 bounded frame TX."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/interface/lora/sx1262_send_frame.S",
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
LORA_ERR_INVAL = 0xFFFFFFFD
LORA_ERR_OVERFLOW = 0xFFFFFFFA
LORA_ERR_TX_TIMEOUT = 0xFFFFFFF9
LORA_ERR_NOT_INITIALIZED = 0xFFFFFFF6
IRQ_TX_DONE = 0x0001
IRQ_TIMEOUT = 0x0200


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
    harness = tmp_path / "sx1262_send_harness.S"
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

    elf = tmp_path / "sx1262_send_harness.elf"
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
        .section .data.sx1262_send_test, "aw", @progbits
        .balign 4
frame3:
        .byte   0x11, 0x22, 0x33
"""


def test_send_frame_writes_fifo_and_observes_tx_done(tmp_path: Path) -> None:
    body = (
        _store_word("spi_model_rx_source", 0x00010000)
        + _call("sx1262_init", 100)
        + _call("sx1262_send_frame", "frame3", 3, 100)
        + _load_word("sx1262_model_tx_len")
        + _load_word("sx1262_model_last_irq")
        + _load_word("spi_model_transfer_count")
        + _load_word("sx1262_frame_tx_buf")
        + _load_word("sx1262_tx_packet_params_buf")
        + _load_word("spi_model_tx_log_len")
        + _load_word("spi_model_tx_log")
    )
    assert _run_body(tmp_path, body, 9, TEST_DATA) == [
        LORA_OK,
        LORA_OK,
        3,
        IRQ_TX_DONE,
        21,
        0x33221100,
        0x03000C00,
        3,
        0x00FFFF02,
    ]


def test_send_frame_rejects_not_initialized_invalid_and_overflow(tmp_path: Path) -> None:
    body = (
        _call("sx1262_send_frame", "frame3", 3, 100)
        + _store_word("sx1262_model_initialized", 1)
        + _call("sx1262_send_frame", 0, 3, 100)
        + _call("sx1262_send_frame", "frame3", 0, 100)
        + _call("sx1262_send_frame", "frame3", 255, 100)
        + _load_word("sx1262_model_tx_len")
    )
    assert _run_body(tmp_path, body, 5, TEST_DATA) == [
        LORA_ERR_NOT_INITIALIZED,
        LORA_ERR_INVAL,
        LORA_ERR_INVAL,
        LORA_ERR_OVERFLOW,
        0,
    ]


def test_send_frame_reports_radio_timeout_irq(tmp_path: Path) -> None:
    body = (
        _store_word("spi_model_rx_source", 0x00000200)
        + _call("sx1262_init", 100)
        + _call("sx1262_send_frame", "frame3", 3, 100)
        + _load_word("sx1262_model_tx_len")
        + _load_word("sx1262_model_last_irq")
    )
    assert _run_body(tmp_path, body, 4, TEST_DATA) == [
        LORA_OK,
        LORA_ERR_TX_TIMEOUT,
        0,
        IRQ_TIMEOUT,
    ]
