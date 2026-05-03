"""Direct QEMU tests for milestone-8 GPIO helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/interface/gpio/gpio_config_output.S",
    "src/interface/gpio/gpio_config_input.S",
    "src/interface/gpio/gpio_write.S",
    "src/interface/gpio/gpio_read.S",
    "src/state/gpio.S",
)

GPIO_OK = 0
GPIO_ERR_INVAL = -1


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

    harness = tmp_path / "gpio_harness.S"
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

    elf = tmp_path / "gpio_harness.elf"
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
        li      t1, {value}
        sw      t1, 0(t0)
"""


def test_output_config_and_write_model(tmp_path: Path) -> None:
    body = (
        _call("gpio_config_output", 0)
        + _load_word("gpio_model_configured")
        + _load_word("gpio_model_direction")
        + _call("gpio_write", 0, 1)
        + _load_word("gpio_model_level")
        + _call("gpio_write", 0, 0)
        + _load_word("gpio_model_level")
    )
    assert _run_body(tmp_path, body, 7) == [
        GPIO_OK,
        0x00000001,
        0x00000001,
        GPIO_OK,
        0x00000001,
        GPIO_OK,
        0x00000000,
    ]


def test_input_config_and_read_model(tmp_path: Path) -> None:
    body = (
        _call("gpio_config_input", 6)
        + _load_word("gpio_model_configured")
        + _load_word("gpio_model_direction")
        + _store_word("gpio_model_level", 1 << 6)
        + _call("gpio_read", 6)
        + _store_word("gpio_model_level", 0)
        + _call("gpio_read", 6)
    )
    assert _run_body(tmp_path, body, 5) == [
        GPIO_OK,
        0x00000040,
        0x00000000,
        1,
        0,
    ]


def test_rejects_wrong_pin_direction_and_level(tmp_path: Path) -> None:
    body = (
        _call("gpio_config_output", 6)
        + _call("gpio_config_input", 7)
        + _call("gpio_config_output", 7)
        + _call("gpio_write", 7, 2)
        + _call("gpio_read", 5)
        + _call("gpio_write", 0, 1)
        + _call("gpio_config_input", 5)
        + _call("gpio_read", 5)
    )
    assert _run_body(tmp_path, body, 8) == [
        0xFFFFFFFF,
        0xFFFFFFFF,
        GPIO_OK,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        GPIO_OK,
        0,
    ]


def test_rejects_disallowed_pins(tmp_path: Path) -> None:
    body = (
        _call("gpio_config_output", 12)
        + _call("gpio_config_input", 12)
        + _call("gpio_write", 12, 1)
        + _call("gpio_read", 12)
        + _call("gpio_config_output", 31)
        + _call("gpio_config_input", 31)
    )
    assert _run_body(tmp_path, body, 6) == [0xFFFFFFFF] * 6
