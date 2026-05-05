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
TRANSPORT_ERR_NOT_FOUND = 0xFFFFFFFE
TRANSPORT_STATUS_DUPLICATE = 2
TRANSPORT_STATUS_FORWARDED = 3
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

        la      t0, packet_seen_stub_return
        sw      zero, 0(t0)
        la      t0, path_lookup_stub_return
        sw      zero, 0(t0)
        la      t0, lora_send_stub_return
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

        .global transport_packet_seen
        .type   transport_packet_seen, @function
transport_packet_seen:
        la      t0, packet_seen_stub_len
        sw      a1, 0(t0)
        lbu     t1, 0(a0)
        la      t0, packet_seen_stub_first
        sw      t1, 0(t0)
        la      t0, packet_seen_stub_return
        lw      a0, 0(t0)
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

        .global transport_path_lookup
        .type   transport_path_lookup, @function
transport_path_lookup:
        la      t0, path_lookup_stub_calls
        lw      t1, 0(t0)
        addi    t1, t1, 1
        sw      t1, 0(t0)
        lbu     t1, 0(a0)
        la      t0, path_lookup_stub_dest0
        sw      t1, 0(t0)
        la      t0, path_lookup_stub_return
        lw      t4, 0(t0)
        bnez    t4, 1f
        li      t2, {TRANSPORT_INTERFACE_LORA}
        sb      t2, 1(a1)
        la      t0, path_lookup_stub_hops
        lw      t2, 0(t0)
        sb      t2, 2(a1)
        la      t0, path_lookup_stub_next_hop
        addi    t1, a1, 104
        li      t2, 16
2:      lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, 2b
1:      mv      a0, t4
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
        la      t0, lora_send_stub_dest0
        sw      t1, 0(t0)
        la      t0, lora_send_stub_return
        lw      a0, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .data.identity_current_test, "aw", @progbits
        .global identity_current
        .type   identity_current, @object
        .balign 16
identity_current:
        .zero   128
        .byte   0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7
        .byte   0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
        .zero   16
        .size   identity_current, 160

        .section .data.transport_process_packet_test_packets, "aw", @progbits
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
h2_packet:
        .byte   0x50, 0x04
        .byte   0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7
        .byte   0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
        .byte   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        .byte   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        .byte   0x00, 0x55
h2_announce_packet:
        .byte   0x51, 0x04
        .byte   0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
        .byte   0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
        .byte   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        .byte   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        .byte   0x00

        .section .data.transport_process_packet_test, "aw", @progbits
announce_stub_return:
        .word   7
packet_seen_stub_return:
        .word   0
packet_seen_stub_len:
        .word   0
packet_seen_stub_first:
        .word   0
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
path_lookup_stub_return:
        .word   0
path_lookup_stub_hops:
        .word   1
path_lookup_stub_calls:
        .word   0
path_lookup_stub_dest0:
        .word   0
path_lookup_stub_next_hop:
        .byte   0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7
        .byte   0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
lora_send_stub_return:
        .word   0
lora_send_stub_len:
        .word   0
lora_send_stub_first:
        .word   0
lora_send_stub_hops:
        .word   0
lora_send_stub_dest0:
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


def _store_word(symbol: str, value: int) -> str:
    return f"""
        la      t0, {symbol}
        li      t1, {value:#x}
        sw      t1, 0(t0)
"""


def test_dispatches_announce_to_transport_handler(tmp_path: Path) -> None:
    body = (
        _call_label("announce_packet", 19)
        + _load_word("announce_stub_len")
        + _load_word("announce_stub_interface")
        + _load_word("announce_stub_first")
        + _load_word("link_stub_len")
        + _load_word("packet_seen_stub_len")
    )
    assert _run_body(tmp_path, body, 6) == [7, 19, TRANSPORT_INTERFACE_LORA, 0x01, 0, 19]


def test_rebroadcasts_accepted_announce_as_header2(tmp_path: Path) -> None:
    body = (
        _store_word("announce_stub_return", 0)
        + _call_label("announce_packet", 19)
        + _load_word("lora_send_stub_len")
        + _load_word("lora_send_stub_first")
        + _load_word("lora_send_stub_hops")
        + _load_word("lora_send_stub_dest0")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 6) == [
        0,
        35,
        0x51,
        4,
        0xA0,
        0,
    ]


def test_rebroadcasts_header2_announce_with_local_transport_id(tmp_path: Path) -> None:
    body = (
        _store_word("announce_stub_return", 0)
        + _call_label("h2_announce_packet", 35)
        + _load_word("lora_send_stub_len")
        + _load_word("lora_send_stub_first")
        + _load_word("lora_send_stub_hops")
        + _load_word("lora_send_stub_dest0")
    )
    assert _run_body(tmp_path, body, 5) == [0, 35, 0x51, 5, 0xA0]


def test_delegates_non_announce_to_link_dispatcher(tmp_path: Path) -> None:
    body = (
        _call_label("data_packet", 19)
        + _load_word("link_stub_len")
        + _load_word("link_stub_interface")
        + _load_word("link_stub_first")
        + _load_word("announce_stub_len")
        + _load_word("packet_seen_stub_first")
    )
    assert _run_body(tmp_path, body, 6) == [8, 19, TRANSPORT_INTERFACE_LORA, 0x00, 0, 0x00]


def test_duplicate_packet_returns_without_dispatch(tmp_path: Path) -> None:
    body = (
        _store_word("packet_seen_stub_return", TRANSPORT_STATUS_DUPLICATE)
        + _call_label("data_packet", 19)
        + _load_word("link_stub_len")
        + _load_word("announce_stub_len")
    )
    assert _run_body(tmp_path, body, 3) == [TRANSPORT_STATUS_DUPLICATE, 0, 0]


def test_forwards_header2_packet_to_one_hop_lora_path(tmp_path: Path) -> None:
    body = (
        _call_label("h2_packet", 36)
        + _load_word("path_lookup_stub_calls")
        + _load_word("path_lookup_stub_dest0")
        + _load_word("lora_send_stub_len")
        + _load_word("lora_send_stub_first")
        + _load_word("lora_send_stub_hops")
        + _load_word("lora_send_stub_dest0")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 8) == [
        TRANSPORT_STATUS_FORWARDED,
        1,
        0x20,
        20,
        0x00,
        5,
        0x20,
        0,
    ]


def test_forwards_header2_packet_to_next_transport_hop(tmp_path: Path) -> None:
    body = (
        _store_word("path_lookup_stub_hops", 2)
        + _call_label("h2_packet", 36)
        + _load_word("path_lookup_stub_calls")
        + _load_word("lora_send_stub_len")
        + _load_word("lora_send_stub_first")
        + _load_word("lora_send_stub_hops")
        + _load_word("lora_send_stub_dest0")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 7) == [
        TRANSPORT_STATUS_FORWARDED,
        1,
        36,
        0x50,
        5,
        0xB0,
        0,
    ]


def test_header2_packet_for_unknown_path_is_not_forwarded(tmp_path: Path) -> None:
    body = (
        _store_word("path_lookup_stub_return", TRANSPORT_ERR_NOT_FOUND)
        + _call_label("h2_packet", 36)
        + _load_word("lora_send_stub_len")
        + _load_word("link_stub_len")
    )
    assert _run_body(tmp_path, body, 3) == [TRANSPORT_ERR_NOT_FOUND, 0, 0]


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
