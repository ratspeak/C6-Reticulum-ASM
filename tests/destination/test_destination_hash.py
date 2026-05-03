"""Tests for src/destination/destination_hash.S.

The byte oracle is upstream RNS.Destination.hash(identity_hash, app, *aspects)
with identity supplied as the 16-byte Reticulum identity hash form.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = Path(__file__).resolve().parents[3] / "upstream" / "Reticulum"

DESTINATION_CASES = (
    ("rnstransport", ("nodes",), bytes(range(16))),
    (
        "lxmf",
        ("delivery",),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ),
    (
        "riscv",
        ("c6", "harness"),
        bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
    ),
)

ASM_SOURCES = (
    "src/destination/destination_hash.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/sha256.S",
)

ZERO_NAME_IDENTITY_HASH = bytes.fromhex("202122232425262728292a2b2c2d2e2f")


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _rns():
    sys.path.insert(0, str(UPSTREAM_RETICULUM))
    import RNS  # type: ignore[import-not-found]

    return RNS


def _name_hash(app_name: str, aspects: tuple[str, ...]) -> bytes:
    rns = _rns()
    expanded = rns.Destination.expand_name(None, app_name, *aspects)
    return rns.Identity.full_hash(expanded.encode("utf-8"))[
        : rns.Identity.NAME_HASH_LENGTH // 8
    ]


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


def _harness_asm(name_hash: bytes, identity_hash: bytes) -> str:
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

        la      a0, name_hash
        la      a1, identity_hash
        la      a2, hash_out
        call    destination_hash

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

        .section .rodata.name_hash, "a"
        .balign 4
name_hash:
        .byte   {_byte_list(name_hash)}

        .section .rodata.identity_hash, "a"
        .balign 4
identity_hash:
        .byte   {_byte_list(identity_hash)}

        .section .bss.hash_out, "aw", @nobits
        .balign 4
hash_out:
        .skip   16
"""


def _build_test_elf(
    tmp_path: Path, name_hash: bytes, identity_hash: bytes,
) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "destination_hash_harness.S"
    harness.write_text(_harness_asm(name_hash, identity_hash), encoding="utf-8")

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

    elf = tmp_path / "destination_hash.elf"
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


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "destination_hash") > 0


def test_calls_sha256_chain(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    assert "sha256_init" in body, body
    assert body.count("sha256_update") >= 2, body
    assert "sha256_final" in body, body


def test_uses_reticulum_hash_lengths(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    for length in (10, 16):
        assert re.search(rf"\bli\b\s+\w+,\s*{length}\b", body), body


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(3)}.issubset(saved), \
        f"expected s0..s2 saved, saw {saved}"


@pytest.mark.parametrize("app_name,aspects,identity_hash", DESTINATION_CASES)
def test_upstream_destination_hash_vectors(
    app_name: str, aspects: tuple[str, ...], identity_hash: bytes,
) -> None:
    rns = _rns()
    name_hash = _name_hash(app_name, aspects)
    expected = hashlib.sha256(name_hash + identity_hash).digest()[:16]
    assert rns.Destination.hash(identity_hash, app_name, *aspects) == expected


def test_zero_length_name_hash_layer_vector() -> None:
    identity_hash = ZERO_NAME_IDENTITY_HASH
    name_hash = hashlib.sha256(b"").digest()[:10]
    expected = hashlib.sha256(name_hash + identity_hash).digest()[:16]
    assert expected.hex() == "9c4a69a5f50a9c8e7b385fd7abfd0ddc"


@pytest.mark.parametrize("app_name,aspects,identity_hash", DESTINATION_CASES)
def test_qemu_destination_hash_vectors(
    tmp_path: Path,
    app_name: str,
    aspects: tuple[str, ...],
    identity_hash: bytes,
) -> None:
    name_hash = _name_hash(app_name, aspects)
    elf = _build_test_elf(tmp_path, name_hash, identity_hash)
    got = _run_qemu(elf)
    expected = oracle.destination_hash(name_hash, identity_hash).hex().encode() + b"\r\n"
    assert got.startswith(expected), f"got {got!r}, expected prefix {expected!r}"


def test_qemu_destination_hash_zero_length_name_vector(tmp_path: Path) -> None:
    name_hash = oracle.destination_name_hash(b"")
    elf = _build_test_elf(tmp_path, name_hash, ZERO_NAME_IDENTITY_HASH)
    got = _run_qemu(elf)
    expected = (
        oracle.destination_hash(name_hash, ZERO_NAME_IDENTITY_HASH).hex().encode()
        + b"\r\n"
    )
    assert got.startswith(expected), f"got {got!r}, expected prefix {expected!r}"
