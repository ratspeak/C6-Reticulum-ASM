"""Direct QEMU tests for transport_process_packet ingress dispatch."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/transport/transport_process_packet.S",
    "src/packet/packet_parse_header.S",
)

TRANSPORT_ERR_INVAL = 0xFFFFFFFF
TRANSPORT_INTERFACE_LORA = 2


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


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

        .global transport_process_announce
        .type   transport_process_announce, @function
transport_process_announce:
        la      t0, announce_stub_len
        sw      a1, 0(t0)
        la      t0, announce_stub_interface
        sw      a2, 0(t0)
        lbu     t1, 0(a0)
        la      t0, announce_stub_first
        sw      t1, 0(t0)
        la      t0, announce_stub_return
        lw      a0, 0(t0)
        ret

        .global link_process_packet
        .type   link_process_packet, @function
link_process_packet:
        la      t0, link_stub_len
        sw      a1, 0(t0)
        la      t0, link_stub_interface
        sw      a2, 0(t0)
        lbu     t1, 0(a0)
        la      t0, link_stub_first
        sw      t1, 0(t0)
        la      t0, link_stub_return
        lw      a0, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .rodata.transport_process_packet_test, "a"
announce_packet:
        .byte   0x01, 0x03
        .byte   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        .byte   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        .byte   0x00
data_packet:
        .byte   0x00, 0x04
        .byte   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        .byte   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        .byte   0x00

        .section .data.transport_process_packet_test, "aw", @progbits
announce_stub_return:
        .word   7
announce_stub_len:
        .word   0
announce_stub_interface:
        .word   0
announce_stub_first:
        .word   0
link_stub_return:
        .word   8
link_stub_len:
        .word   0
link_stub_interface:
        .word   0
link_stub_first:
        .word   0
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")
    harness = tmp_path / "transport_process_packet_harness.S"
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

    elf = tmp_path / "transport_process_packet.elf"
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


def _call_label(label: str, length: int, interface_id: int = TRANSPORT_INTERFACE_LORA) -> str:
    return f"""
        la      a0, {label}
        li      a1, {length}
        li      a2, {interface_id}
        call    transport_process_packet
        call    .Lemit_hex32_line
"""


def _call_null(length: int) -> str:
    return f"""
        mv      a0, zero
        li      a1, {length}
        li      a2, {TRANSPORT_INTERFACE_LORA}
        call    transport_process_packet
        call    .Lemit_hex32_line
"""


def _load_word(symbol: str) -> str:
    return f"""
        la      t0, {symbol}
        lw      a0, 0(t0)
        call    .Lemit_hex32_line
"""


def test_dispatches_announce_to_transport_handler(tmp_path: Path) -> None:
    body = (
        _call_label("announce_packet", 19)
        + _load_word("announce_stub_len")
        + _load_word("announce_stub_interface")
        + _load_word("announce_stub_first")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 5) == [7, 19, TRANSPORT_INTERFACE_LORA, 0x01, 0]


def test_delegates_non_announce_to_link_dispatcher(tmp_path: Path) -> None:
    body = (
        _call_label("data_packet", 19)
        + _load_word("link_stub_len")
        + _load_word("link_stub_interface")
        + _load_word("link_stub_first")
        + _load_word("announce_stub_len")
    )
    assert _run_body(tmp_path, body, 5) == [8, 19, TRANSPORT_INTERFACE_LORA, 0x00, 0]


def test_rejects_truncated_packet_without_dispatch(tmp_path: Path) -> None:
    body = (
        _call_label("announce_packet", 18)
        + _load_word("announce_stub_len")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 3) == [TRANSPORT_ERR_INVAL, 0, 0]


def test_rejects_null_packet_without_dispatch(tmp_path: Path) -> None:
    body = (
        _call_null(19)
        + _load_word("announce_stub_len")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 3) == [TRANSPORT_ERR_INVAL, 0, 0]


def test_registered_symbol_present(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "transport_process_packet") > 0
