"""Direct QEMU tests for src/announce/announce_validate.S."""

from __future__ import annotations

import dataclasses
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/announce/announce_parse.S",
    "src/announce/announce_validate.S",
    "src/packet/packet_parse_header.S",
    "src/identity/identity_hash.S",
    "src/destination/destination_hash.S",
    "src/crypto/ed25519/ed25519_verify.S",
    "src/crypto/ed25519/ed25519_point_decompress.S",
    "src/crypto/ed25519/ed25519_field_pow_p5d8.S",
    "src/crypto/ed25519/ed25519_scalarmult.S",
    "src/crypto/ed25519/ed25519_point_add.S",
    "src/crypto/ed25519/ed25519_point_double.S",
    "src/crypto/ed25519/ed25519_point_compress.S",
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
    "src/state/announce.S",
    "src/state/ed25519.S",
    "src/state/sha512.S",
    "src/state/sha256.S",
)

ANNOUNCE_RX_OFF_APP_DATA_PTR = 176


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    raw_packet: bytes
    expected_rc: int
    expect_pyca: bool | None = None
    null_parsed: bool = False
    post_parse: str = ""


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


def _valid_packet(app_data: bytes = b"payload") -> bytes:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    identity = oracle.identity_from_private_parts(bytes(range(32)), bytes(range(32, 64)))
    name_hash = oracle.destination_name_hash_from_parts("rnstransport", "nodes")
    random_hash = bytes(range(10))
    return oracle.announce_build(identity, name_hash, random_hash, app_data).raw_packet


def _h2_packet(raw: bytes) -> bytes:
    transport_id = bytes(range(0xA0, 0xB0))
    return bytes([0x51, raw[1]]) + transport_id + raw[2:]


def _tampered(raw: bytes, offset: int) -> bytes:
    out = bytearray(raw)
    out[offset] ^= 0x01
    return bytes(out)


def _case(name: str) -> Case:
    raw = _valid_packet()
    tamper_offsets = {
        "tampered-destination-hash": 2,
        "tampered-public-key": 19,
        "tampered-name-hash": 83,
        "tampered-random-hash": 93,
        "tampered-signature": 103,
        "tampered-app-data": len(raw) - 1,
    }
    if name == "valid":
        return Case(name, raw, 0, expect_pyca=True)
    if name == "valid-h2-transport":
        return Case(name, _h2_packet(raw), 0, expect_pyca=None)
    if name == "valid-empty-app":
        return Case(name, _valid_packet(b""), 0, expect_pyca=True)
    if name == "null-parsed":
        return Case(name, raw, -1, expect_pyca=None, null_parsed=True)
    if name == "null-app-pointer":
        post_parse = f"""
        la      t0, parsed
        sw      zero, {ANNOUNCE_RX_OFF_APP_DATA_PTR}(t0)
"""
        return Case(name, raw, -1, expect_pyca=None, post_parse=post_parse)
    if name in tamper_offsets:
        return Case(name, _tampered(raw, tamper_offsets[name]), -1, expect_pyca=False)
    raise ValueError(f"unknown case {name}")


def _harness_asm(case: Case) -> str:
    if case.null_parsed:
        body = """
        mv      a0, zero
        call    announce_validate
"""
    else:
        body = f"""
        la      a0, raw_packet
        li      a1, {len(case.raw_packet)}
        la      a2, parsed
        call    announce_parse
        blt     a0, zero, .Lemit_result
{case.post_parse}
        la      a0, parsed
        call    announce_validate
"""
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

.Lemit_result:
        call    .Lemit_hex32
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

        .size   _reset, . - _reset

        .section .data.raw_packet, "aw", @progbits
        .balign 4
raw_packet:
        .byte   {_byte_list(case.raw_packet)}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   180
"""


def _build_test_elf(tmp_path: Path, case: Case) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "announce_validate_harness.S"
    harness.write_text(_harness_asm(case), encoding="utf-8")

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

    elf = tmp_path / "announce_validate.elf"
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
        for _ in range(240):
            out.extend(emu.read(1024, timeout=0.5))
            if b"\n" in out:
                break
    return bytes(out)


def _parse_ret(output: bytes) -> int:
    ret_u32 = int(output.splitlines()[0], 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "announce_validate") > 0


def test_static_calls_required_components(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_validate")
    for callee in ("identity_hash", "destination_hash", "ed25519_verify"):
        assert callee in body
    assert "announce_signed_data" in body


def test_static_length_and_error_shape(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_validate")
    assert re.search(r"\bli\b\s+\w+,\s*167\b", body), body
    assert re.search(r"\bli\b\s+\w+,\s*484\b", body), body
    assert re.search(r"\bli\b\s+a0,\s*-1\b", body), body


@pytest.mark.parametrize(
    "name",
    [
        "valid",
        "valid-h2-transport",
        "valid-empty-app",
        "tampered-destination-hash",
        "tampered-public-key",
        "tampered-name-hash",
        "tampered-random-hash",
        "tampered-signature",
        "tampered-app-data",
        "null-parsed",
        "null-app-pointer",
    ],
)
def test_announce_validate_qemu(tmp_path: Path, name: str) -> None:
    case = _case(name)
    if case.expect_pyca is not None:
        assert oracle.announce_validate_pyca(case.raw_packet) is case.expect_pyca

    ret = _parse_ret(_run_qemu(_build_test_elf(tmp_path, case)))
    assert ret == case.expected_rc
