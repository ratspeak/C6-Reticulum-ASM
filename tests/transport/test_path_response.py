"""Direct QEMU tests for Reticulum transport path-response helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/transport/transport_path_response_cache_update.S",
    "src/transport/transport_path_response_send.S",
    "src/transport/transport_path_init.S",
    "src/transport/transport_path_lookup.S",
    "src/state/transport.S",
    "src/state/identity.S",
)

TRANSPORT_STATUS_FORWARDED = 3
TRANSPORT_ERR_INVAL = 0xFFFFFFFF
TRANSPORT_ERR_NOT_FOUND = 0xFFFFFFFE
TRANSPORT_INTERFACE_LORA = 2

DEST_HASH = bytes(range(0x10, 0x20))
LOCAL_TRANSPORT_ID = bytes(range(0xA0, 0xB0))
NEXT_HOP = bytes(range(0xC0, 0xD0))
OTHER_REQUESTOR = bytes(range(0xD0, 0xE0))
H1_RAW = bytes([0x01, 0x03]) + DEST_HASH + bytes([0x00, 0xAA, 0xBB])
H2_RAW = (
    bytes([0x51, 0x06])
    + bytes(range(0x70, 0x80))
    + DEST_HASH
    + bytes([0x00, 0xCC])
)


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


def _byte_list(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


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

        la      t0, lora_send_stub_return
        sw      zero, 0(t0)
        call    .Lseed_identity

{body}

.Lhalt:
        wfi
        j       .Lhalt

.Lseed_identity:
        la      t0, identity_current
        addi    t0, t0, 128
        la      t1, local_transport_id
        li      t2, 16
1:      lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, 1b
        ret

.Lseed_path:
        la      t0, transport_path_table
        li      t1, 1
        sb      t1, 0(t0)
        li      t1, {TRANSPORT_INTERFACE_LORA}
        sb      t1, 1(t0)
        li      t1, 4
        sb      t1, 2(t0)
        sw      zero, 4(t0)
        la      t1, dest_hash
        addi    t2, t0, 8
        li      t3, 16
2:      lbu     t4, 0(t1)
        sb      t4, 0(t2)
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        bnez    t3, 2b
        la      t1, next_hop
        addi    t2, t0, 104
        li      t3, 16
3:      lbu     t4, 0(t1)
        sb      t4, 0(t2)
        addi    t1, t1, 1
        addi    t2, t2, 1
        addi    t3, t3, -1
        bnez    t3, 3b
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
4:      srl     t4, t2, t3
        andi    a0, t4, 15
        call    .Lnibble_to_ascii
        call    .Lputc
        addi    t3, t3, -4
        bgez    t3, 4b
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 5f
        addi    a0, a0, 87
        ret
5:      addi    a0, a0, 48
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
6:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 6b
        sb      a0, 0(t0)
        ret

.Lemit_cache_fields:
        addi    sp, sp, -16
        sw      s0, 0(sp)
        sw      ra, 12(sp)
        la      s0, transport_path_response_cache
        lbu     a0, 0(s0)
        call    .Lemit_hex32_line
        lw      a0, 4(s0)
        call    .Lemit_hex32_line
        lbu     a0, 24(s0)
        call    .Lemit_hex32_line
        lbu     a0, 25(s0)
        call    .Lemit_hex32_line
        lbu     a0, 26(s0)
        call    .Lemit_hex32_line
        lbu     a0, 42(s0)
        call    .Lemit_hex32_line
        lbu     a0, 58(s0)
        call    .Lemit_hex32_line
        lbu     a0, 59(s0)
        call    .Lemit_hex32_line
        lw      s0, 0(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .global lora_interface_send
        .type   lora_interface_send, @function
lora_interface_send:
        la      t0, lora_send_stub_len
        sw      a1, 0(t0)
        lbu     t1, 0(a0)
        la      t0, lora_send_stub_first
        sw      t1, 0(t0)
        lbu     t1, 1(a0)
        la      t0, lora_send_stub_hops
        sw      t1, 0(t0)
        lbu     t1, 2(a0)
        la      t0, lora_send_stub_tid0
        sw      t1, 0(t0)
        lbu     t1, 18(a0)
        la      t0, lora_send_stub_dest0
        sw      t1, 0(t0)
        lbu     t1, 34(a0)
        la      t0, lora_send_stub_context
        sw      t1, 0(t0)
        la      t0, lora_send_stub_return
        lw      a0, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .data.path_response_test_packets, "aw", @progbits
h1_raw:
        .byte   {_byte_list(H1_RAW)}
h2_raw:
        .byte   {_byte_list(H2_RAW)}
dest_hash:
        .byte   {_byte_list(DEST_HASH)}
local_transport_id:
        .byte   {_byte_list(LOCAL_TRANSPORT_ID)}
next_hop:
        .byte   {_byte_list(NEXT_HOP)}
other_requestor:
        .byte   {_byte_list(OTHER_REQUESTOR)}

        .section .data.path_response_test_state, "aw", @progbits
lora_send_stub_return:
        .word   0
lora_send_stub_len:
        .word   0
lora_send_stub_first:
        .word   0
lora_send_stub_hops:
        .word   0
lora_send_stub_tid0:
        .word   0
lora_send_stub_dest0:
        .word   0
lora_send_stub_context:
        .word   0
"""


def _build_test_elf(tmp_path: Path, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")
    harness = tmp_path / "path_response_harness.S"
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

    elf = tmp_path / "path_response.elf"
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


def _run_qemu(tmp_path: Path, body: str, line_count: int) -> list[int]:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, body))
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
    return [int(line, 16) for line in lines[:line_count]]


def _load_word(symbol: str) -> str:
    return f"""
        la      t0, {symbol}
        lw      a0, 0(t0)
        call    .Lemit_hex32_line
"""


def test_cache_update_builds_header2_path_response_from_header1(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        la      a0, h1_raw
        li      a1, {len(H1_RAW)}
        li      a2, 4
        call    transport_path_response_cache_update
        call    .Lemit_hex32_line
        call    .Lemit_cache_fields
"""
    assert _run_qemu(tmp_path, body, 9) == [
        0,
        1,
        len(H1_RAW) + 16,
        0x51,
        4,
        LOCAL_TRANSPORT_ID[0],
        DEST_HASH[0],
        0x0B,
        0xAA,
    ]


def test_cache_update_normalizes_header2_path_response(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        la      a0, h2_raw
        li      a1, {len(H2_RAW)}
        li      a2, 7
        call    transport_path_response_cache_update
        call    .Lemit_hex32_line
        call    .Lemit_cache_fields
"""
    assert _run_qemu(tmp_path, body, 9) == [
        0,
        1,
        len(H2_RAW),
        0x51,
        7,
        LOCAL_TRANSPORT_ID[0],
        DEST_HASH[0],
        0x0B,
        0xCC,
    ]


def test_send_for_known_cached_path_emits_lora_response(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        la      a0, h1_raw
        li      a1, {len(H1_RAW)}
        li      a2, 4
        call    transport_path_response_cache_update
        call    .Lseed_path
        la      a0, dest_hash
        mv      a1, zero
        li      a2, {TRANSPORT_INTERFACE_LORA}
        call    transport_path_response_send
        call    .Lemit_hex32_line
{_load_word("lora_send_stub_len")}
{_load_word("lora_send_stub_first")}
{_load_word("lora_send_stub_hops")}
{_load_word("lora_send_stub_tid0")}
{_load_word("lora_send_stub_dest0")}
{_load_word("lora_send_stub_context")}
"""
    assert _run_qemu(tmp_path, body, 7) == [
        TRANSPORT_STATUS_FORWARDED,
        len(H1_RAW) + 16,
        0x51,
        4,
        LOCAL_TRANSPORT_ID[0],
        DEST_HASH[0],
        0x0B,
    ]


def test_send_suppresses_requestor_equal_to_next_hop(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        la      a0, h1_raw
        li      a1, {len(H1_RAW)}
        li      a2, 4
        call    transport_path_response_cache_update
        call    .Lseed_path
        la      a0, dest_hash
        la      a1, next_hop
        li      a2, {TRANSPORT_INTERFACE_LORA}
        call    transport_path_response_send
        call    .Lemit_hex32_line
{_load_word("lora_send_stub_len")}
"""
    assert _run_qemu(tmp_path, body, 2) == [TRANSPORT_ERR_NOT_FOUND, 0]


def test_send_rejects_missing_cache_or_wrong_interface(tmp_path: Path) -> None:
    body = f"""
        call    transport_path_init
        call    .Lseed_path
        la      a0, dest_hash
        la      a1, other_requestor
        li      a2, {TRANSPORT_INTERFACE_LORA}
        call    transport_path_response_send
        call    .Lemit_hex32_line
        la      a0, dest_hash
        mv      a1, zero
        li      a2, 1
        call    transport_path_response_send
        call    .Lemit_hex32_line
"""
    assert _run_qemu(tmp_path, body, 2) == [
        TRANSPORT_ERR_NOT_FOUND,
        TRANSPORT_ERR_NOT_FOUND,
    ]


def test_functions_exist(artifacts: build.BuildArtifacts) -> None:
    for name in ("transport_path_response_cache_update", "transport_path_response_send"):
        assert build.symbol_address(artifacts.elf, name) > 0
