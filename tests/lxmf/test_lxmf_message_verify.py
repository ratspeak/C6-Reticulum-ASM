"""Direct QEMU tests for LXMF message signature verification."""

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
    "src/lxmf/lxmf_message_verify.S",
    "src/lxmf/lxmf_message_id.S",
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

MAX_PAYLOAD = 397


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
PAYLOAD = msgpack.packb([1.5, b"Title", b"Body", {}])
ALT_PAYLOAD = msgpack.packb([1.5, b"Title", b"Body! ", {}])


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    dest: bytes = DEST
    source: bytes = IDENTITY.hash
    payload: bytes = PAYLOAD
    sign_payload: bytes = PAYLOAD
    public_key: bytes = IDENTITY.ed25519_public
    expect_ret: int = 0
    flip_sig: bool = False
    null_dest: bool = False
    null_source: bool = False
    null_payload: bool = False
    null_sig: bool = False
    null_pk: bool = False


CASES = (
    Case("valid"),
    Case("bad-signature", expect_ret=-5, flip_sig=True),
    Case("tampered-payload", payload=ALT_PAYLOAD, sign_payload=PAYLOAD, expect_ret=-5),
    Case("wrong-public-key", public_key=WRONG_IDENTITY.ed25519_public, expect_ret=-5),
    Case("null-dest", expect_ret=-1, null_dest=True),
    Case("null-source", expect_ret=-1, null_source=True),
    Case("null-payload", expect_ret=-1, null_payload=True),
    Case("null-sig", expect_ret=-1, null_sig=True),
    Case("null-pk", expect_ret=-1, null_pk=True),
    Case("zero-payload-len", payload=b"", sign_payload=b"", expect_ret=-1),
    Case("payload-overflow", payload=bytes(MAX_PAYLOAD + 1), sign_payload=PAYLOAD, expect_ret=-2),
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

.Lnibble_to_ascii:
        li      t0, 10
        bltu    a0, t0, 2f
        addi    a0, a0, 87
        ret
2:      addi    a0, a0, 48
        ret

.Lputc:
        li      t0, 0x10000000
3:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 3b
        sb      a0, 0(t0)
        ret
"""


def _harness(case: Case) -> str:
    dest_ptr = "mv      a0, zero" if case.null_dest else "la      a0, dest_hash"
    source_ptr = "mv      a1, zero" if case.null_source else "la      a1, source_hash"
    payload_ptr = "mv      a2, zero" if case.null_payload else "la      a2, payload"
    sig_ptr = "mv      a4, zero" if case.null_sig else "la      a4, signature"
    pk_ptr = "mv      a5, zero" if case.null_pk else "la      a5, source_pk"
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
        {sig_ptr}
        {pk_ptr}
        call    lxmf_message_verify
        call    .Lemit_hex32
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
signature:
        .byte   {_byte_list(_signature(case))}
source_pk:
        .byte   {_byte_list(case.public_key)}
"""


def _build_test_elf(tmp_path: Path, asm: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "lxmf_message_verify_harness.S"
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

    elf = tmp_path / "lxmf_message_verify.elf"
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
    assert build.symbol_address(artifacts.elf, "lxmf_message_verify") > 0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_lxmf_message_verify_qemu(tmp_path: Path, case: Case) -> None:
    ret = _parse_ret(_run_qemu(tmp_path, _harness(case)))
    assert ret == case.expect_ret
