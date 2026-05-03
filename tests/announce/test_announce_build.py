"""Direct QEMU tests for src/announce/announce_build.S."""

from __future__ import annotations

import dataclasses
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, drbg_oracle, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/announce/announce_build.S",
    "src/identity/identity_create.S",
    "src/identity/identity_hash.S",
    "src/destination/destination_hash.S",
    "src/crypto/x25519/x25519_keypair.S",
    "src/crypto/x25519/x25519_scalar_mult.S",
    "src/crypto/x25519/x25519_montgomery_ladder.S",
    "src/crypto/x25519/x25519_decode_scalar.S",
    "src/crypto/x25519/x25519_cswap.S",
    "src/crypto/x25519/x25519_field_unpack.S",
    "src/crypto/x25519/x25519_field_pack.S",
    "src/crypto/x25519/x25519_field_add.S",
    "src/crypto/x25519/x25519_field_sub.S",
    "src/crypto/x25519/x25519_field_mul.S",
    "src/crypto/x25519/x25519_field_sq.S",
    "src/crypto/x25519/x25519_field_mul121665.S",
    "src/crypto/x25519/x25519_field_inv.S",
    "src/crypto/ed25519/ed25519_keypair.S",
    "src/crypto/ed25519/ed25519_sign.S",
    "src/crypto/ed25519/ed25519_scalarmult.S",
    "src/crypto/ed25519/ed25519_point_add.S",
    "src/crypto/ed25519/ed25519_point_double.S",
    "src/crypto/ed25519/ed25519_point_compress.S",
    "src/crypto/ed25519/ed25519_sc_reduce.S",
    "src/crypto/ed25519/ed25519_sc_muladd.S",
    "src/crypto/sha512/sha512_init.S",
    "src/crypto/sha512/sha512_update.S",
    "src/crypto/sha512/sha512_final.S",
    "src/crypto/sha512/sha512_compress.S",
    "src/crypto/rng/rng_init.S",
    "src/crypto/rng/rng_entropy.S",
    "src/crypto/rng/rng_bytes.S",
    "src/crypto/rng/hmac_drbg_update.S",
    "src/crypto/hmac/hmac_sha256.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/announce.S",
    "src/state/x25519.S",
    "src/state/ed25519.S",
    "src/state/sha512.S",
    "src/state/rng.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
)

ANNOUNCE_BASE_RAW_LEN = 167
RETICULUM_MDU = 484
MAX_APP_DATA = RETICULUM_MDU - ANNOUNCE_BASE_RAW_LEN


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    app_data: bytes
    capacity_delta: int = 0
    expect_overflow: bool = False


CASES = (
    Case("empty-app", b""),
    Case("non-empty-app", b"hello announce"),
    Case("exact-capacity", bytes((i * 17 + 3) & 0xFF for i in range(MAX_APP_DATA))),
    Case("one-byte-short-overflow", b"overflow", capacity_delta=-1, expect_overflow=True),
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
    return ", ".join(f"0x{b:02x}" for b in data)


def _expected_identity_and_random() -> tuple[oracle.IdentityMaterial, bytes]:
    k, v = drbg_oracle.drbg_instantiate()
    x25519_sk, k, v = drbg_oracle.drbg_generate(k, v, 32)
    ed25519_seed, k, v = drbg_oracle.drbg_generate(k, v, 32)
    random_hash, _k, _v = drbg_oracle.drbg_generate(k, v, 10)
    return oracle.identity_from_private_parts(x25519_sk, ed25519_seed), random_hash


def _harness_asm(name_hash: bytes, app_data: bytes, capacity: int) -> str:
    if app_data:
        app_ptr = "la      a2, app_data"
    else:
        app_ptr = "mv      a2, zero"
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

        call    rng_init
        la      a0, identity_out
        call    identity_create

        la      a0, identity_out
        la      a1, name_hash
        {app_ptr}
        li      a3, {len(app_data)}
        la      a4, raw_out
        li      a5, {capacity}
        call    announce_build

        mv      s2, a0
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s2, zero, .Lemit_done
        la      a0, raw_out
        mv      a1, s2
        call    .Lemit_bytes

.Lemit_done:
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

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

        .size   _reset, . - _reset

        .section .rodata.name_hash, "a"
        .balign 4
name_hash:
        .byte   {_byte_list(name_hash)}

        .section .rodata.app_data, "a"
        .balign 4
app_data:
        .byte   {_byte_list(app_data)}

        .section .bss.identity_out, "aw", @nobits
        .balign 16
identity_out:
        .skip   160

        .section .bss.raw_out, "aw", @nobits
        .balign 4
raw_out:
        .skip   {RETICULUM_MDU}
"""


def _build_test_elf(
    tmp_path: Path, name_hash: bytes, app_data: bytes, capacity: int,
) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "announce_build_harness.S"
    harness.write_text(_harness_asm(name_hash, app_data, capacity), encoding="utf-8")

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

    elf = tmp_path / "announce_build.elf"
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
        for _ in range(180):
            out.extend(emu.read(1024, timeout=0.5))
            if b"\n" in out:
                break
    return bytes(out)


def _parse_output(output: bytes) -> tuple[int, bytes]:
    line = output.splitlines()[0]
    ret_hex, _, raw_hex = line.partition(b":")
    ret_u32 = int(ret_hex, 16)
    ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
    raw = bytes.fromhex(raw_hex.decode()) if raw_hex else b""
    return ret, raw


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "announce_build") > 0
    assert build.symbol_address(artifacts.elf, "announce_signed_data") > 0


def test_calls_required_components(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_build")
    for callee in ("destination_hash", "rng_bytes", "ed25519_sign"):
        assert callee in body, f"{callee} not called: {body}"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_announce_build_qemu(tmp_path: Path, case: Case) -> None:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    raw_len = ANNOUNCE_BASE_RAW_LEN + len(case.app_data)
    capacity = raw_len + case.capacity_delta
    elf = _build_test_elf(tmp_path, name_hash, case.app_data, capacity)

    ret, raw = _parse_output(_run_qemu(elf))

    if case.expect_overflow:
        assert ret == -1
        assert raw == b""
        return

    identity, random_hash = _expected_identity_and_random()
    expected = oracle.announce_build(identity, name_hash, random_hash, case.app_data)

    assert ret == len(expected.raw_packet) == raw_len
    assert raw == expected.raw_packet
    assert raw[0] == oracle.HEADER_1_ANNOUNCE_FLAGS
    assert raw[1] == oracle.HEADER_1_HOPS
    assert raw[18] == oracle.PACKET_CONTEXT_NONE
    assert oracle.announce_parse(raw) == expected
    assert oracle.announce_validate_pyca(raw)
    if importlib.util.find_spec("RNS") is not None:
        assert oracle.announce_validate_upstream(raw)
