"""Direct QEMU tests for milestone-7 resource reassembly initialization."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/resource/resource_reassembly_init.S",
    "src/state/resource.S",
)

REASSEMBLY_CAPACITY = 2
REASSEMBLY_MAX_PARTS = 64
RESOURCE_MAPHASH_SIZE = 4
REASM_BITMAP_BYTES = 8
REASM_HASHMAP_BYTES = 256
REASM_ENTRY_SIZE = 316
REASM_TABLE_SIZE = 632


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
"""


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

.Lfill_table:
        la      t0, resource_reassembly_table
        li      t1, {REASM_TABLE_SIZE}
        li      t2, 0xaa
6:      beqz    t1, 7f
        sb      t2, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        j       6b
7:      ret

{_emit_helpers()}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "resource_reassembly_init_harness.S"
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

    elf = tmp_path / "resource_reassembly_init.elf"
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


def _run_qemu(tmp_path: Path, body: str) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, _harness_asm(body)))
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


def _parse_line(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, table_hex = line.partition(b":")
    ret_u32 = int(ret_hex, 16)
    ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
    return ret, bytes.fromhex(table_hex.decode())


def _init_and_emit_body(*, second_init: bool = False) -> str:
    maybe_second = "        call    resource_reassembly_init" if second_init else ""
    return f"""
        call    .Lfill_table
        call    resource_reassembly_init
{maybe_second}
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        la      a0, resource_reassembly_table
        li      a1, {REASM_TABLE_SIZE}
        call    .Lemit_bytes
        call    .Lnewline
"""


def test_layout_constants_are_intentional() -> None:
    assert REASSEMBLY_CAPACITY == 2
    assert REASSEMBLY_MAX_PARTS == 64
    assert RESOURCE_MAPHASH_SIZE == 4
    assert REASM_BITMAP_BYTES == REASSEMBLY_MAX_PARTS // 8
    assert REASM_HASHMAP_BYTES == REASSEMBLY_MAX_PARTS * RESOURCE_MAPHASH_SIZE
    assert REASM_ENTRY_SIZE == 316
    assert REASM_TABLE_SIZE == REASSEMBLY_CAPACITY * REASM_ENTRY_SIZE


def test_symbols_exist(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "resource_reassembly_init") > 0
    assert build.symbol_address(artifacts.elf, "resource_reassembly_table") > 0


def test_init_zeroes_prefilled_table(tmp_path: Path) -> None:
    ret, table = _parse_line(_run_qemu(tmp_path, _init_and_emit_body()))
    assert ret == 0
    assert len(table) == REASM_TABLE_SIZE
    assert table == bytes(REASM_TABLE_SIZE)


def test_init_is_idempotent(tmp_path: Path) -> None:
    ret, table = _parse_line(_run_qemu(tmp_path, _init_and_emit_body(second_init=True)))
    assert ret == 0
    assert table == bytes(REASM_TABLE_SIZE)
