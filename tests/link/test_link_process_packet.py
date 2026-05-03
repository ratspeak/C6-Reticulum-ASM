"""Direct QEMU tests for milestone-6 link_process_packet dispatch."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/link/link_process_packet.S",
    "src/link/link_request_parse.S",
    "src/packet/packet_parse_header.S",
    "src/state/link.S",
)

LINK_STATUS_DECRYPTED = 2
LINK_STATUS_DUPLICATE = 1
LINK_ERR_INVAL = -1

LINK_ID = bytes((0x40 + i * 3) & 0xFF for i in range(16))
OTHER_LINK_ID = bytes((0xA0 + i * 5) & 0xFF for i in range(16))
TOKEN_OK = bytes([0x01]) + bytes((0x55 + i) & 0xFF for i in range(63))
TOKEN_BAD = bytes([0xEE]) + bytes((0x77 + i) & 0xFF for i in range(63))
DEST = bytes((0x20 + i * 7) & 0xFF for i in range(16))
DUP_DEST = bytes([0xDD]) + DEST[1:]
XPUB = bytes((0x10 + i) & 0xFF for i in range(32))
EPUB = bytes((0x80 + i) & 0xFF for i in range(32))

REQUEST_OK = oracle.link_request_build(DEST, XPUB, EPUB).raw_packet
REQUEST_DUP = oracle.link_request_build(DUP_DEST, XPUB, EPUB).raw_packet
REQUEST_BAD = REQUEST_OK[:-1] + b"\x00"


def _link_data(link_id: bytes, token: bytes, *, context: int = 0) -> bytes:
    return bytes([0x0C, 0x00]) + link_id + bytes([context]) + token


ANNOUNCE_MINIMAL = bytes([0x01, 0x00]) + DEST + b"\x00"


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    raw: bytes
    expect_ret: int
    expect_scratch2: bytes = b"\x00\x00"
    expect_announce_seen: int = 0
    populate_link: bool = False


SCENARIOS = (
    Scenario("link-request-accepted", REQUEST_OK, 0),
    Scenario("link-request-duplicate", REQUEST_DUP, LINK_STATUS_DUPLICATE),
    Scenario("link-request-invalid", REQUEST_BAD, LINK_ERR_INVAL),
    Scenario(
        "encrypted-link-data",
        _link_data(LINK_ID, TOKEN_OK),
        LINK_STATUS_DECRYPTED,
        b"ok",
        populate_link=True,
    ),
    Scenario(
        "encrypted-link-data-unknown-id",
        _link_data(OTHER_LINK_ID, TOKEN_OK),
        LINK_ERR_INVAL,
        populate_link=True,
    ),
    Scenario(
        "encrypted-link-data-decrypt-fail",
        _link_data(LINK_ID, TOKEN_BAD),
        LINK_ERR_INVAL,
        populate_link=True,
    ),
    Scenario(
        "encrypted-link-data-wrong-context",
        _link_data(LINK_ID, TOKEN_OK, context=1),
        LINK_ERR_INVAL,
        populate_link=True,
    ),
    Scenario("announce-preserved", ANNOUNCE_MINIMAL, 0, expect_announce_seen=1),
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


def _populate_link_code(enabled: bool) -> str:
    if not enabled:
        return ""
    return """
        la      t0, link_table
        li      t1, 1
        sb      t1, LINK_ENTRY_OFF_VALID(t0)
        li      t1, LINK_STATUS_ESTABLISHED
        sb      t1, LINK_ENTRY_OFF_STATUS(t0)
        li      t1, LINK_MODE_AES256_CBC
        sb      t1, LINK_ENTRY_OFF_MODE(t0)

        la      a0, link_id
        la      a1, link_table
        addi    a1, a1, LINK_ENTRY_OFF_LINK_ID
        li      a2, LINK_ID_SIZE
        call    .Lcopy_bytes
"""


def _emit_helpers() -> str:
    return """
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

.Lputc:
        li      t0, 0x10000000
7:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 7b
        sb      a0, 0(t0)
        ret

.Lcopy_bytes:
        beqz    a2, 9f
8:      lbu     t0, 0(a0)
        sb      t0, 0(a1)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        bnez    a2, 8b
9:      ret
"""


def _stubs() -> str:
    return """
        .global link_handshake_accept
        .type   link_handshake_accept, @function
link_handshake_accept:
        lbu     t0, LINK_REQUEST_OFF_DEST_HASH(a0)
        li      t1, 0xdd
        beq     t0, t1, 1f
        li      a0, LINK_OK
        ret
1:      li      a0, LINK_STATUS_DUPLICATE
        ret

        .global link_session_decrypt
        .type   link_session_decrypt, @function
link_session_decrypt:
        lbu     t0, 0(a1)
        li      t1, 0xee
        beq     t0, t1, 2f
        li      t0, 0x6f
        sb      t0, 0(a3)
        li      t0, 0x6b
        sb      t0, 1(a3)
        li      a0, 2
        ret
2:      li      a0, LINK_ERR_INVAL
        ret

        .global transport_process_announce
        .type   transport_process_announce, @function
transport_process_announce:
        la      t0, announce_seen
        li      t1, 1
        sb      t1, 0(t0)
        li      a0, 0
        ret
"""


def _harness_asm(scenario: Scenario) -> str:
    return f"""
        .include "link.S"

        .section .text._reset, "ax", @progbits
        .global _reset
        .type   _reset, @function
_reset:
        la      sp, __stack_top

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

{_populate_link_code(scenario.populate_link)}
        la      a0, raw_packet
        li      a1, {len(scenario.raw)}
        li      a2, 1
        call    link_process_packet

        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        la      a0, link_session_scratch
        li      a1, 2
        call    .Lemit_bytes
        li      a0, 58
        call    .Lputc
        la      a0, announce_seen
        li      a1, 1
        call    .Lemit_bytes
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}
{_stubs()}

        .section .rodata.input, "a", @progbits
raw_packet:
        .byte   {_byte_list(scenario.raw)}
link_id:
        .byte   {_byte_list(LINK_ID)}

        .section .bss.announce_seen, "aw", @nobits
announce_seen:
        .skip   1
"""


def _build_test_elf(tmp_path: Path, scenario: Scenario) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "link_process_packet_harness.S"
    harness.write_text(_harness_asm(scenario), encoding="utf-8")

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

    elf = tmp_path / "link_process_packet.elf"
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


def _run_qemu(tmp_path: Path, scenario: Scenario) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, scenario))
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(120):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= 1:
                break
    return bytes(out).splitlines()[0]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def _parse_output(line: bytes) -> tuple[int, bytes, int]:
    ret_hex, scratch_hex, seen_hex = line.split(b":")
    return _parse_ret(ret_hex), bytes.fromhex(scratch_hex.decode()), int(seen_hex, 16)


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_process_packet") > 0


def test_dispatch_calls_dependencies(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_process_packet")
    assert "packet_parse_header" in body
    assert "link_request_parse" in body
    assert "link_handshake_accept" in body
    assert "link_session_decrypt" in body
    assert "transport_process_announce" in body


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_link_process_packet_qemu(tmp_path: Path, scenario: Scenario) -> None:
    ret, scratch2, announce_seen = _parse_output(_run_qemu(tmp_path, scenario))
    assert ret == scenario.expect_ret
    assert scratch2 == scenario.expect_scratch2
    assert announce_seen == scenario.expect_announce_seen
