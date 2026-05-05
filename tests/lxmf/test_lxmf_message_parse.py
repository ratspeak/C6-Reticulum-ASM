"""Direct QEMU tests for LXMF message parsing and signature verification."""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
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
    "src/lxmf/lxmf_message_parse.S",
    "src/lxmf/lxmf_payload_parse.S",
    "src/lxmf/lxmf_message_id.S",
    "src/lxmf/lxmf_message_verify.S",
    "src/crypto/ed25519/ed25519_verify.S",
    "src/crypto/ed25519/ed25519_scalarmult.S",
    "src/crypto/ed25519/ed25519_point_add.S",
    "src/crypto/ed25519/ed25519_point_double.S",
    "src/crypto/ed25519/ed25519_point_compress.S",
    "src/crypto/ed25519/ed25519_point_decompress.S",
    "src/crypto/ed25519/ed25519_field_pow_p5d8.S",
    "src/crypto/ed25519/ed25519_sc_reduce.S",
    "src/crypto/x25519/x25519_field_add.S",
    "src/crypto/x25519/x25519_field_sub.S",
    "src/crypto/x25519/x25519_field_mul.S",
    "src/crypto/x25519/x25519_field_sq.S",
    "src/crypto/x25519/x25519_field_inv.S",
    "src/crypto/x25519/x25519_field_pack.S",
    "src/crypto/x25519/x25519_field_unpack.S",
    "src/crypto/sha512/sha512_init.S",
    "src/crypto/sha512/sha512_update.S",
    "src/crypto/sha512/sha512_final.S",
    "src/crypto/sha512/sha512_compress.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/ed25519.S",
    "src/state/x25519.S",
    "src/state/sha512.S",
    "src/state/sha256.S",
)

HASH_SIZE = 16
SIGNATURE_SIZE = 64
PACKED_PREFIX = 96
PARSED_SIZE = 516
MAX_STAMPED = 431


def _identity_material(seed: bytes) -> oracle.IdentityMaterial:
    xsk = bytes((i * 7 + 3) & 0xFF for i in range(32))
    return oracle.identity_from_private_parts(xsk, seed)


IDENTITY = _identity_material(
    bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
)
WRONG_IDENTITY = _identity_material(bytes([0xA5]) * 32)
DEST = bytes(range(16))
NO_STAMP = msgpack.packb([1.5, b"Title", b"Body", {}])
ALT_PAYLOAD = msgpack.packb([1.5, b"Title", b"Body!", {}])
STAMP16 = bytes([0x95]) + NO_STAMP[1:] + b"\xc4\x10" + (b"\x11" * 16)


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    payload: bytes = NO_STAMP
    sign_payload: bytes = NO_STAMP
    dest: bytes = DEST
    source: bytes = IDENTITY.hash
    public_key: bytes = IDENTITY.ed25519_public
    expect_ret: int = 0
    flip_sig: bool = False
    raw_override: bytes | None = None
    null_raw: bool = False
    null_out: bool = False
    null_pk: bool = False


def _signature(case: Case) -> bytes:
    message_id = hashlib.sha256(case.dest + case.source + case.sign_payload).digest()
    sig = bytearray(
        oracle.ed25519_sign(
            IDENTITY.ed25519_seed,
            case.dest + case.source + case.sign_payload + message_id,
        )
    )
    if case.flip_sig:
        sig[0] ^= 0x01
    return bytes(sig)


def _packed(case: Case) -> bytes:
    if case.raw_override is not None:
        return case.raw_override
    return case.dest + case.source + _signature(case) + case.payload


CASES = (
    Case("basic"),
    Case("stamped", payload=STAMP16, sign_payload=NO_STAMP),
    Case("bad-signature", expect_ret=-5, flip_sig=True),
    Case("tampered-payload", payload=ALT_PAYLOAD, sign_payload=NO_STAMP, expect_ret=-5),
    Case("wrong-public-key", public_key=WRONG_IDENTITY.ed25519_public, expect_ret=-5),
    Case("short-prefix", raw_override=bytes(PACKED_PREFIX - 1), expect_ret=-6),
    Case("malformed-payload", raw_override=DEST + IDENTITY.hash + bytes(SIGNATURE_SIZE) + b"\x93", expect_ret=-1),
    Case(
        "payload-overflow",
        raw_override=DEST + IDENTITY.hash + bytes(SIGNATURE_SIZE) + bytes(MAX_STAMPED + 1),
        expect_ret=-2,
    ),
    Case("null-raw", expect_ret=-1, null_raw=True),
    Case("null-out", expect_ret=-1, null_out=True),
    Case("null-pk", expect_ret=-1, null_pk=True),
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

.Lemit_sep:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      a0, 58
        call    .Lputc
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
    raw = _packed(case)
    raw_ptr = "mv      a0, zero" if case.null_raw else "la      a0, packed_msg"
    out_ptr = "mv      a2, zero" if case.null_out else "la      a2, parsed"
    pk_ptr = "mv      a3, zero" if case.null_pk else "la      a3, source_pk"
    return f"""
        .include "lxmf.S"

        .section .text._reset, "ax", @progbits
        .global _reset
        .type   _reset, @function
_reset:
        la      sp, __stack_top

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

        {raw_ptr}
        li      a1, {len(raw)}
        {out_ptr}
        {pk_ptr}
        call    lxmf_message_parse
        mv      s0, a0
        call    .Lemit_hex32
        blt     s0, zero, .Ldone

        call    .Lemit_sep
        la      t0, parsed
        addi    a0, t0, LXMF_MESSAGE_PARSED_OFF_MESSAGE_ID
        li      a1, 32
        call    .Lemit_bytes

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_LEN(t0)
        call    .Lemit_hex32

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_LEN(t0)
        call    .Lemit_hex32

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_SOURCE_HASH_PTR(t0)
        li      a1, 16
        call    .Lemit_bytes

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_SIGNATURE_PTR(t0)
        li      a1, 64
        call    .Lemit_bytes

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_PTR(t0)
        lw      a1, LXMF_MESSAGE_PARSED_OFF_PAYLOAD_LEN(t0)
        call    .Lemit_bytes

        call    .Lemit_sep
        la      t0, parsed
        lw      a0, LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_PTR(t0)
        lw      a1, LXMF_MESSAGE_PARSED_OFF_WITHOUT_STAMP_LEN(t0)
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
packed_msg:
        .byte   {_byte_list(raw)}
source_pk:
        .byte   {_byte_list(case.public_key)}

        .section .bss.output, "aw", @nobits
        .balign 4
parsed:
        .skip   {PARSED_SIZE}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_message_parse_harness.S"
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

    elf = tmp_path / "lxmf_message_parse.elf"
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


def _parse_line(line: bytes) -> tuple[int, list[bytes]]:
    parts = line.split(b":")
    ret = _parse_ret(parts[0])
    if ret < 0:
        return ret, []
    return ret, [bytes.fromhex(p.decode()) for p in parts[1:]]


def _u32(data: bytes) -> int:
    return int.from_bytes(data, "big")


def test_symbol_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "lxmf_message_parse") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_message_parse_qemu(tmp_path: Path, case: Case) -> None:
    ret, outputs = _parse_line(_run_qemu(tmp_path, _harness(case)))
    assert ret == case.expect_ret
    if ret < 0:
        assert outputs == []
        return

    message_id, payload_len, without_len, source, signature, payload, without = outputs
    assert message_id == hashlib.sha256(case.dest + case.source + case.sign_payload).digest()
    assert _u32(payload_len) == len(case.payload)
    assert _u32(without_len) == len(case.sign_payload)
    assert source == case.source
    assert signature == _signature(case)
    assert payload == case.payload
    assert without == case.sign_payload
