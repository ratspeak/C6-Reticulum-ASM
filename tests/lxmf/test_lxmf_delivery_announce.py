"""Direct QEMU tests for LXMF delivery announce app-data."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))

import RNS.vendor.umsgpack as msgpack  # noqa: E402

ASM_SOURCES = ("src/lxmf/lxmf_delivery_announce_build.S",)

MAX_NAME = 255
MAX_APP_DATA = 260


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    display_name: bytes | None
    stamp_cost: int
    cap: int = MAX_APP_DATA
    expect_ret: int | None = None
    null_out: bool = False
    force_null_name_with_len: bool = False


CASES = (
    Case("nil-nil", None, 0),
    Case("name-nil", b"Test", 0),
    Case("name-fixint-cost", b"Test", 16),
    Case("name-uint8-cost", b"Test", 128),
    Case("name-max-uint8-cost", b"Test", 254),
    Case("empty-name", b"", 1),
    Case("max-name", bytes(range(MAX_NAME)), 254),
    Case("cost-255-is-nil", b"Test", 255),
    Case("cap-overflow", b"Test", 16, cap=7, expect_ret=-2),
    Case("name-overflow", bytes(range(256)), 16, expect_ret=-2),
    Case("null-name-nonzero-len", b"bad", 16, expect_ret=-1, force_null_name_with_len=True),
    Case("null-out", b"Test", 16, expect_ret=-1, null_out=True),
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt", force=True)


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


def _expected(case: Case) -> bytes:
    encoded_name = case.display_name
    encoded_cost = case.stamp_cost if 0 < case.stamp_cost < 255 else None
    return msgpack.packb([encoded_name, encoded_cost])


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
"""


def _harness(case: Case) -> str:
    if case.display_name is None or case.force_null_name_with_len:
        name_ptr = "mv      a0, zero"
        name_len = len(case.display_name or b"")
    else:
        name_ptr = "la      a0, display_name"
        name_len = len(case.display_name)
    out_ptr = "mv      a3, zero" if case.null_out else "la      a3, app_data_out"
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

        {name_ptr}
        li      a1, {name_len}
        li      a2, {case.stamp_cost}
        {out_ptr}
        li      a4, {case.cap}
        call    lxmf_delivery_announce_build
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, app_data_out
        mv      a1, s0
        call    .Lemit_bytes
.Ldone:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc
.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}

        .section .rodata.input, "a", @progbits
display_name:
        .byte   {_byte_list(case.display_name or b"")}

        .section .bss.output, "aw", @nobits
        .balign 4
app_data_out:
        .skip   {MAX_APP_DATA}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_delivery_announce_harness.S"
    harness.write_text(asm, encoding="utf-8")

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

    elf = tmp_path / "lxmf_delivery_announce.elf"
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


def _run_qemu(tmp_path: Path, asm: str) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, asm))
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


def _parse_line(line: bytes) -> tuple[int, bytes | None]:
    ret_hex, _, payload_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    if ret < 0:
        return ret, None
    return ret, bytes.fromhex(payload_hex.decode())


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_delivery_announce_build") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_delivery_announce_build_qemu(tmp_path: Path, case: Case) -> None:
    ret, payload = _parse_line(_run_qemu(tmp_path, _harness(case)))
    if case.expect_ret is not None:
        assert ret == case.expect_ret
        assert payload is None
        return
    expected = _expected(case)
    assert ret == len(expected)
    assert payload == expected


def test_expected_vectors_match_upstream_msgpack() -> None:
    assert _expected(Case("nil-nil", None, 0)).hex() == "92c0c0"
    assert _expected(Case("fixint", b"Test", 16)).hex() == "92c4045465737410"
    assert _expected(Case("uint8", b"Test", 128)).hex() == "92c40454657374cc80"
