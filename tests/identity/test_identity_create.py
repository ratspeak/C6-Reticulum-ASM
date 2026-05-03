"""QEMU layout KAT for src/identity/identity_create.S.

The production dispatcher does not own identity_create yet, so this test
builds a tiny qemu-virt ELF that initialises the deterministic RNG, calls
identity_create directly, and emits the 160-byte identity_t as hex.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, drbg_oracle, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/identity/identity_create.S",
    "src/identity/identity_hash.S",
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
    "src/crypto/ed25519/ed25519_scalarmult.S",
    "src/crypto/ed25519/ed25519_point_add.S",
    "src/crypto/ed25519/ed25519_point_double.S",
    "src/crypto/ed25519/ed25519_point_compress.S",
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
    "src/state/x25519.S",
    "src/state/ed25519.S",
    "src/state/sha512.S",
    "src/state/rng.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
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


def _expected_identity() -> bytes:
    k, v = drbg_oracle.drbg_instantiate()
    x25519_sk, k, v = drbg_oracle.drbg_generate(k, v, 32)
    ed25519_seed, _k, _v = drbg_oracle.drbg_generate(k, v, 32)
    material = oracle.identity_from_private_parts(x25519_sk, ed25519_seed)
    return material.private_key + material.public_key + material.hash + bytes(16)


def _harness_asm() -> str:
    return """
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

        la      s0, identity_out
        li      s1, 160
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

        .section .bss.identity_out, "aw", @nobits
        .balign 16
identity_out:
        .skip   160
"""


def _build_test_elf(tmp_path: Path) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "identity_create_harness.S"
    harness.write_text(_harness_asm(), encoding="utf-8")

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

    elf = tmp_path / "identity_create.elf"
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
        for _ in range(120):
            out.extend(emu.read(512, timeout=0.5))
            if b"\n" in out:
                break
    return bytes(out)


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "identity_create") > 0


def test_calls_component_functions(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="identity_create")
    for callee in ("x25519_keypair", "ed25519_keypair", "identity_hash"):
        assert callee in body, f"{callee} not called: {body}"


def test_identity_create_qemu_layout(tmp_path: Path) -> None:
    elf = _build_test_elf(tmp_path)
    got = _run_qemu(elf)
    expected = _expected_identity()
    expected_hex = expected.hex().encode() + b"\r\n"
    assert got.startswith(expected_hex), f"got {got!r}, expected {expected_hex!r}"

    assert expected[:64] == (
        oracle.identity_private_key(expected[:32], expected[32:64])
    )
    assert expected[128:144] == hashlib.sha256(expected[64:128]).digest()[:16]
    assert expected[144:160] == bytes(16)

