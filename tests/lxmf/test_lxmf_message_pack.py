"""Direct QEMU tests for LXMF message packing."""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_RETICULUM = REPO_ROOT.parent / "upstream" / "Reticulum"
sys.path.insert(0, str(UPSTREAM_RETICULUM))

import RNS.vendor.umsgpack as msgpack  # noqa: E402

ASM_SOURCES = (
    "src/lxmf/lxmf_message_pack.S",
    "src/lxmf/lxmf_payload_build.S",
    "src/lxmf/lxmf_message_sign.S",
    "src/lxmf/lxmf_message_id.S",
    "src/identity/identity_load.S",
    "src/identity/identity_hash.S",
    "src/flash/flash_init.S",
    "src/flash/flash_read.S",
    "src/flash/flash_write_page.S",
    "src/crypto/ed25519/ed25519_sign.S",
    "src/crypto/ed25519/ed25519_scalarmult.S",
    "src/crypto/ed25519/ed25519_point_add.S",
    "src/crypto/ed25519/ed25519_point_double.S",
    "src/crypto/ed25519/ed25519_point_compress.S",
    "src/crypto/ed25519/ed25519_sc_reduce.S",
    "src/crypto/ed25519/ed25519_sc_muladd.S",
    "src/crypto/x25519/x25519_field_add.S",
    "src/crypto/x25519/x25519_field_sub.S",
    "src/crypto/x25519/x25519_field_mul.S",
    "src/crypto/x25519/x25519_field_sq.S",
    "src/crypto/x25519/x25519_field_inv.S",
    "src/crypto/x25519/x25519_field_pack.S",
    "src/crypto/sha512/sha512_init.S",
    "src/crypto/sha512/sha512_update.S",
    "src/crypto/sha512/sha512_final.S",
    "src/crypto/sha512/sha512_compress.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/identity.S",
    "src/state/flash.S",
    "src/state/ed25519.S",
    "src/state/x25519.S",
    "src/state/sha512.S",
    "src/state/sha256.S",
)

IDENTITY_T_SIZE = 160
RECORD_SIZE = 256
MAX_TITLE = 64
MAX_CONTENT = 255
MAX_PAYLOAD = 397
PACKED_PREFIX = 96
MAX_PACKED = PACKED_PREFIX + MAX_PAYLOAD


def _identity_material() -> oracle.IdentityMaterial:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    esk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    return oracle.identity_from_private_parts(xsk, esk)


IDENTITY = _identity_material()
IDENTITY_BYTES = IDENTITY.private_key + IDENTITY.public_key + IDENTITY.hash + bytes(16)
DEST = bytes(range(16))
CUSTOM_FIELDS = msgpack.packb({0xFB: b"abc"})


def _record(identity: bytes) -> bytes:
    assert len(identity) == IDENTITY_T_SIZE
    out = bytearray([0xFF] * RECORD_SIZE)
    out[0:4] = b"RID1"
    out[4] = 1
    out[5] = 0
    out[6:8] = (48).to_bytes(2, "little")
    out[8:12] = IDENTITY_T_SIZE.to_bytes(4, "little")
    out[12:16] = bytes(4)
    out[48:208] = identity
    out[16:48] = hashlib.sha256(bytes(out[0:16]) + identity).digest()
    return bytes(out)


VALID_RECORD = _record(IDENTITY_BYTES)


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    timestamp: float = 1.5
    title: bytes = b"Title"
    content: bytes = b"Body"
    fields: bytes = b""
    dest: bytes = DEST
    source: bytes = IDENTITY.hash
    cap: int = MAX_PACKED
    expect_ret: int | None = None
    preload_identity: bool = True
    null_dest: bool = False
    null_source: bool = False
    null_input: bool = False
    null_out: bool = False
    null_timestamp: bool = False


CASES = (
    Case("basic"),
    Case("custom-fields", fields=CUSTOM_FIELDS),
    Case("exact-cap", cap=PACKED_PREFIX + len(msgpack.packb([1.5, b"Title", b"Body", {}]))),
    Case("cap-below-prefix", cap=PACKED_PREFIX - 1, expect_ret=-2),
    Case("payload-cap-overflow", cap=PACKED_PREFIX + 8, expect_ret=-2),
    Case("missing-identity", preload_identity=False, expect_ret=-3),
    Case("source-mismatch", source=bytes(16), expect_ret=-1),
    Case("bad-fields-marker", fields=b"\xc0", expect_ret=-1),
    Case("title-overflow", title=b"A" * (MAX_TITLE + 1), expect_ret=-2),
    Case("content-overflow", content=b"B" * (MAX_CONTENT + 1), expect_ret=-2),
    Case("null-dest", null_dest=True, expect_ret=-1),
    Case("null-source", null_source=True, expect_ret=-1),
    Case("null-input", null_input=True, expect_ret=-1),
    Case("null-out", null_out=True, expect_ret=-1),
    Case("null-timestamp", null_timestamp=True, expect_ret=-1),
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


def _payload(case: Case) -> bytes:
    fields_obj = msgpack.unpackb(case.fields) if case.fields else {}
    return msgpack.packb([case.timestamp, case.title, case.content, fields_obj])


def _expected_packed(case: Case) -> bytes:
    payload = _payload(case)
    message_id = hashlib.sha256(case.dest + case.source + payload).digest()
    sig = oracle.ed25519_sign(
        IDENTITY.ed25519_seed,
        case.dest + case.source + payload + message_id,
    )
    return case.dest + case.source + sig + payload


def _expected_ret(case: Case) -> int:
    return case.expect_ret if case.expect_ret is not None else len(_expected_packed(case))


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
5:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 5b
        sb      a0, 0(t0)
        ret
"""


def _harness(case: Case) -> str:
    dest_ptr = "mv      a0, zero" if case.null_dest else "la      a0, dest_hash"
    source_ptr = "mv      a1, zero" if case.null_source else "la      a1, source_hash"
    input_ptr = "mv      a2, zero" if case.null_input else "la      a2, payload_input"
    out_ptr = "mv      a3, zero" if case.null_out else "la      a3, packed_out"
    timestamp_ptr = "0" if case.null_timestamp else "timestamp_be"
    if case.fields:
        fields_ptr = "fields"
        fields_len = len(case.fields)
    else:
        fields_ptr = "0"
        fields_len = 0
    preload = """
        li      a0, 0
        la      a1, record_data
        li      a2, 256
        call    flash_write_page
""" if case.preload_identity else ""
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

        call    flash_init
{preload}
        {dest_ptr}
        {source_ptr}
        {input_ptr}
        {out_ptr}
        li      a4, {case.cap}
        call    lxmf_message_pack
        mv      s0, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s0, zero, .Ldone
        la      a0, packed_out
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
timestamp_be:
        .byte   {_byte_list(struct.pack(">d", case.timestamp))}
title:
        .byte   {_byte_list(case.title)}
content:
        .byte   {_byte_list(case.content)}
fields:
        .byte   {_byte_list(case.fields)}
dest_hash:
        .byte   {_byte_list(case.dest)}
source_hash:
        .byte   {_byte_list(case.source)}
record_data:
        .byte   {_byte_list(VALID_RECORD)}

        .section .data.input, "aw", @progbits
        .balign 4
payload_input:
        .word   {timestamp_ptr}
        .word   title
        .word   {len(case.title)}
        .word   content
        .word   {len(case.content)}
        .word   {fields_ptr}
        .word   {fields_len}

        .section .bss.output, "aw", @nobits
        .balign 4
packed_out:
        .skip   {MAX_PACKED}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_message_pack_harness.S"
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

    elf = tmp_path / "lxmf_message_pack.elf"
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
        for _ in range(240):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= 1:
                break
    return bytes(out).splitlines()[0]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_message_pack") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_message_pack_qemu(tmp_path: Path, case: Case) -> None:
    line = _run_qemu(tmp_path, _harness(case))
    ret_hex, data_hex = line.split(b":", 1)
    ret = _parse_ret(ret_hex)
    assert ret == _expected_ret(case)
    if ret >= 0:
        assert bytes.fromhex(data_hex.decode("ascii")) == _expected_packed(case)
