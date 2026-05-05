"""Direct QEMU tests for one-frame LoRa interface RX polling."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/interface/lora/lora_interface_poll.S",
    "src/interface/lora/sx1262_poll_receive.S",
    "src/interface/lora/sx1262_command_write.S",
    "src/interface/lora/sx1262_command_read.S",
    "src/interface/gpio/gpio_config_output.S",
    "src/interface/gpio/gpio_config_input.S",
    "src/interface/gpio/gpio_write.S",
    "src/interface/gpio/gpio_read.S",
    "src/interface/spi/spi_transfer.S",
    "src/clock/clock_delay_us.S",
    "src/state/gpio.S",
    "src/state/spi.S",
    "src/state/lora.S",
)

LORA_ERR_NO_PACKET = 0xFFFFFFF8
LORA_ERR_CRC = 0xFFFFFFF7
LORA_ERR_NOT_INITIALIZED = 0xFFFFFFF6
TRANSPORT_ERR_INVAL = 0xFFFFFFFF
TRANSPORT_STATUS_UPDATED = 1
GPIO_DIO1_MASK = 1 << 5
IRQ_RX_DONE = 0x0002
IRQ_CRC_ERR = 0x0040
TRANSPORT_INTERFACE_LORA = 2


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
        la      t0, sx1262_model_rx_len
        sw      zero, 0(t0)
        la      t0, lora_interface_initialized
        sw      zero, 0(t0)
        la      t0, lora_interface_last_status
        sw      zero, 0(t0)
        la      t0, lora_interface_tx_len
        sw      zero, 0(t0)
        la      t0, lora_interface_rx_len
        sw      zero, 0(t0)
        la      t0, lora_interface_dispatch_status
        sw      zero, 0(t0)
        la      t0, transport_stub_raw_len
        sw      zero, 0(t0)
        la      t0, transport_stub_interface
        sw      zero, 0(t0)
        la      t0, transport_stub_return
        li      t1, {TRANSPORT_STATUS_UPDATED}
        sw      t1, 0(t0)

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

        .global transport_process_packet
        .type   transport_process_packet, @function
transport_process_packet:
        la      t0, transport_stub_raw_len
        sw      a1, 0(t0)
        la      t0, transport_stub_interface
        sw      a2, 0(t0)
        la      t0, transport_stub_return
        lw      a0, 0(t0)
        ret

        .size   _reset, . - _reset
{data}
"""


def _build_test_elf(tmp_path: Path, body: str, data: str = "") -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")
    harness = tmp_path / "lora_interface_poll_harness.S"
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

    elf = tmp_path / "lora_interface_poll_harness.elf"
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


def _store_byte(symbol: str, offset: int, value: int) -> str:
    return f"""
        la      t0, {symbol}
        li      t1, {value:#x}
        sb      t1, {offset}(t0)
"""


TEST_DATA = """
        .section .data.lora_interface_poll_test, "aw", @progbits
        .balign 4
transport_stub_return:
        .word   1
transport_stub_raw_len:
        .word   0
transport_stub_interface:
        .word   0
"""


def _ready_radio() -> str:
    return (
        _store_word("spi_model_initialized", 1)
        + _store_word("sx1262_model_initialized", 1)
        + _store_word("lora_interface_initialized", 1)
    )


def test_lora_interface_poll_dispatches_received_frame(tmp_path: Path) -> None:
    body = (
        _ready_radio()
        + _store_word("gpio_model_level", GPIO_DIO1_MASK)
        + _store_word("spi_model_rx_source", 0x44020000)
        + _store_byte("spi_model_rx_source", 4, 0x55)
        + _call("lora_interface_poll", 100)
        + _load_word("lora_interface_rx_len")
        + _load_word("lora_interface_last_status")
        + _load_word("lora_interface_dispatch_status")
        + _load_word("lora_interface_rx_buf")
        + _load_word("sx1262_model_last_irq")
        + _load_word("spi_model_transfer_count")
        + _load_word("transport_stub_raw_len")
        + _load_word("transport_stub_interface")
    )
    assert _run_body(tmp_path, body, 9, TEST_DATA) == [
        TRANSPORT_STATUS_UPDATED,
        2,
        TRANSPORT_STATUS_UPDATED,
        TRANSPORT_STATUS_UPDATED,
        0x00005544,
        IRQ_RX_DONE,
        5,
        2,
        TRANSPORT_INTERFACE_LORA,
    ]


def test_lora_interface_poll_returns_no_packet_without_dispatch(tmp_path: Path) -> None:
    body = (
        _ready_radio()
        + _call("lora_interface_poll", 100)
        + _load_word("lora_interface_rx_len")
        + _load_word("lora_interface_last_status")
        + _load_word("lora_interface_dispatch_status")
        + _load_word("spi_model_transfer_count")
        + _load_word("transport_stub_raw_len")
    )
    assert _run_body(tmp_path, body, 6, TEST_DATA) == [
        LORA_ERR_NO_PACKET,
        0,
        LORA_ERR_NO_PACKET,
        0,
        1,
        0,
    ]


def test_lora_interface_poll_requires_interface_init(tmp_path: Path) -> None:
    body = (
        _store_word("spi_model_initialized", 1)
        + _store_word("sx1262_model_initialized", 1)
        + _call("lora_interface_poll", 100)
        + _load_word("lora_interface_rx_len")
        + _load_word("lora_interface_last_status")
        + _load_word("spi_model_transfer_count")
        + _load_word("transport_stub_raw_len")
    )
    assert _run_body(tmp_path, body, 5, TEST_DATA) == [
        LORA_ERR_NOT_INITIALIZED,
        0,
        LORA_ERR_NOT_INITIALIZED,
        0,
        0,
    ]


def test_lora_interface_poll_records_radio_crc_without_dispatch(tmp_path: Path) -> None:
    body = (
        _ready_radio()
        + _store_word("gpio_model_level", GPIO_DIO1_MASK)
        + _store_word("spi_model_rx_source", 0x00400000)
        + _call("lora_interface_poll", 100)
        + _load_word("lora_interface_rx_len")
        + _load_word("lora_interface_last_status")
        + _load_word("sx1262_model_last_irq")
        + _load_word("spi_model_transfer_count")
        + _load_word("transport_stub_raw_len")
    )
    assert _run_body(tmp_path, body, 6, TEST_DATA) == [
        LORA_ERR_CRC,
        0,
        LORA_ERR_CRC,
        IRQ_CRC_ERR,
        3,
        0,
    ]


def test_lora_interface_poll_records_dispatch_error(tmp_path: Path) -> None:
    body = (
        _ready_radio()
        + _store_word("gpio_model_level", GPIO_DIO1_MASK)
        + _store_word("spi_model_rx_source", 0x44020000)
        + _store_byte("spi_model_rx_source", 4, 0x55)
        + _store_word("transport_stub_return", TRANSPORT_ERR_INVAL)
        + _call("lora_interface_poll", 100)
        + _load_word("lora_interface_rx_len")
        + _load_word("lora_interface_last_status")
        + _load_word("lora_interface_dispatch_status")
        + _load_word("transport_stub_raw_len")
        + _load_word("transport_stub_interface")
    )
    assert _run_body(tmp_path, body, 6, TEST_DATA) == [
        TRANSPORT_ERR_INVAL,
        2,
        TRANSPORT_ERR_INVAL,
        TRANSPORT_ERR_INVAL,
        2,
        TRANSPORT_INTERFACE_LORA,
    ]
