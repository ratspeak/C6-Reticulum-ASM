"""Direct QEMU tests for LXMF message-id hashing."""

from __future__ import annotations

import dataclasses
import hashlib
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

ASM_SOURCES = (
    "src/lxmf/lxmf_message_id.S",
    "src/state/sha256.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
)

HASH_SIZE = 16
MESSAGE_ID_SIZE = 32
MAX_PAYLOAD = 397


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    dest: bytes
    source: bytes
    payload: bytes
    expect_ret: int = 0
    null_dest: bool = False
    null_source: bool = False
    null_payload: bool = False
    null_out: bool = False


DEST = bytes(range(16))
SOURCE = bytes(range(16, 32))
NO_STAMP = msgpack.packb([1.5, b"Title", b"Body", {}])
STAMPED = msgpack.packb([1.5, b"T", b"C", {}, b"\x11" * 16])
STAMPED_WITHOUT = msgpack.packb(msgpack.unpackb(STAMPED)[:4])
MAX_BOUND_PAYLOAD = msgpack.packb([1.5, bytes(range(64)), bytes(range(255)), {0xFB: b"A" * 58}])

CASES = (
    Case("basic", DEST, SOURCE, NO_STAMP),
    Case("empty-title-content", DEST, SOURCE, msgpack.packb([1700000000.0, b"", b"", {}])),
    Case("custom-fields", DEST, SOURCE, msgpack.packb([1.5, b"", b"", {0xFB: b"abc"}])),
    Case("stamped-without", DEST, SOURCE, STAMPED_WITHOUT),
    Case("max-bound-payload", DEST, SOURCE, MAX_BOUND_PAYLOAD),
    Case("null-dest", DEST, SOURCE, NO_STAMP, -1, null_dest=True),
    Case("null-source", DEST, SOURCE, NO_STAMP, -1, null_source=True),
    Case("null-payload", DEST, SOURCE, NO_STAMP, -1, null_payload=True),
    Case("null-out", DEST, SOURCE, NO_STAMP, -1, null_out=True),
    Case("zero-payload-len", DEST, SOURCE, b"", -1),
    Case("payload-overflow", DEST, SOURCE, bytes(MAX_PAYLOAD + 1), -2),
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
    dest_ptr = "mv      a0, zero" if case.null_dest else "la      a0, dest_hash"
    source_ptr = "mv      a1, zero" if case.null_source else "la      a1, source_hash"
    payload_ptr = "mv      a2, zero" if case.null_payload else "la      a2, payload"
    out_ptr = "mv      a4, zero" if case.null_out else "la      a4, out_digest"
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

        {dest_ptr}
        {source_ptr}
        {payload_ptr}
        li      a3, {len(case.payload)}
        {out_ptr}
        call    lxmf_message_id
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, out_digest
        li      a1, {MESSAGE_ID_SIZE}
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
dest_hash:
        .byte   {_byte_list(case.dest)}
source_hash:
        .byte   {_byte_list(case.source)}
payload:
        .byte   {_byte_list(case.payload)}

        .section .bss.output, "aw", @nobits
        .balign 4
out_digest:
        .skip   {MESSAGE_ID_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_message_id_harness.S"
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

    elf = tmp_path / "lxmf_message_id.elf"
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
    ret_hex, _, digest_hex = line.partition(b":")
    ret = _parse_ret(ret_hex)
    if ret < 0:
        return ret, None
    return ret, bytes.fromhex(digest_hex.decode())


def _expected(case: Case) -> bytes:
    return hashlib.sha256(case.dest + case.source + case.payload).digest()


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_message_id") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_message_id_qemu(tmp_path: Path, case: Case) -> None:
    ret, digest = _parse_line(_run_qemu(tmp_path, _harness(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert digest is None
        return
    assert digest == _expected(case)


def test_known_vector() -> None:
    assert _expected(CASES[0]).hex() == "98917cbfc56ec420599f5c833742f860ed5f027b1a1567a1762c454b8caa4db4"
