"""QEMU vectors for src/identity/identity_hash.S.

The production `_main` dispatcher is owned by Agent 1, so these tests build
a tiny qemu-virt ELF that calls identity_hash directly and emits the 16-byte
result as hex over the qemu NS16550A UART.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/identity/identity_hash.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/sha256.S",
)

VECTORS = (
    pytest.param(bytes(64), id="zero64"),
    pytest.param(bytes(range(64)), id="seq64"),
    pytest.param(bytes([0xFF] * 64), id="ff64"),
    pytest.param(bytes(((i * 37 + 11) & 0xFF) for i in range(64)), id="affine64"),
)


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
    return ", ".join(f"0x{b:02x}" for b in data)


def _harness_asm(public_key: bytes) -> str:
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

        la      a0, public_key
        la      a1, hash_out
        call    identity_hash

        la      s0, hash_out
        li      s1, 16
.Lemit_loop:
        beqz    s1, .Lemit_done
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
        j       .Lemit_loop

.Lemit_done:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 1f
        addi    a0, a0, 87
        ret
1:      addi    a0, a0, 48
        ret

.Lputc:
        li      t0, 0x10000000
2:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 2b
        sb      a0, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .rodata.public_key, "a"
        .balign 4
public_key:
        .byte   {_byte_list(public_key)}

        .section .bss.hash_out, "aw", @nobits
        .balign 4
hash_out:
        .skip   16
"""


def _build_test_elf(tmp_path: Path, public_key: bytes) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "identity_hash_harness.S"
    harness.write_text(_harness_asm(public_key), encoding="utf-8")

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

    elf = tmp_path / "identity_hash.elf"
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


def _run_qemu(elf: Path) -> bytes:
    cfg = target.TargetConfig(binary=elf)
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(8):
            out.extend(emu.read(64, timeout=0.5))
            if b"\n" in out:
                break
    return bytes(out)


@pytest.mark.parametrize("public_key", VECTORS)
def test_identity_hash_qemu_vectors(tmp_path: Path, public_key: bytes) -> None:
    elf = _build_test_elf(tmp_path, public_key)
    got = _run_qemu(elf)
    expected = hashlib.sha256(public_key).digest()[:16].hex().encode() + b"\r\n"
    assert got.startswith(expected), f"got {got!r}, expected prefix {expected!r}"

