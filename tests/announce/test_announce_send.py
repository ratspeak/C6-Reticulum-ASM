"""Direct QEMU tests for src/announce/announce_send.S."""

from __future__ import annotations

import dataclasses
import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, drbg_oracle, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/announce/announce_send.S",
    "src/announce/announce_build.S",
    "src/kiss/kiss_encode_frame.S",
    "src/log/log_hex.S",
    "src/clock/clock_now_ms.S",
    "src/clock/clock_now_ticks.S",
    "src/uart/uart_tx_bytes.S",
    "src/uart/uart_tx_byte.S",
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
    expect_failure: bool = False


CASES = (
    Case("empty-app", b""),
    Case("non-empty-app-with-kiss-escapes", b"hello\xc0\xdbannounce"),
    Case("overflow", bytes((i * 11 + 5) & 0xFF for i in range(MAX_APP_DATA + 1)), True),
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


def _harness_asm(name_hash: bytes, app_data: bytes) -> str:
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
        call    announce_send

        mv      s2, a0
        la      a0, ret_prefix
        li      a1, 4
        call    uart_tx_bytes
        mv      a0, s2
        li      a1, 8
        call    log_hex
        li      a0, 13
        call    uart_tx_byte
        li      a0, 10
        call    uart_tx_byte

.Lhalt:
        wfi
        j       .Lhalt

        .size   _reset, . - _reset

        .section .rodata.name_hash, "a"
        .balign 4
name_hash:
        .byte   {_byte_list(name_hash)}

        .section .rodata.app_data, "a"
        .balign 4
app_data:
        .byte   {_byte_list(app_data)}

        .section .rodata.ret_prefix, "a"
ret_prefix:
        .ascii  "RET="

        .section .bss.identity_out, "aw", @nobits
        .balign 16
identity_out:
        .skip   160
"""


def _build_test_elf(tmp_path: Path, name_hash: bytes, app_data: bytes) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "announce_send_harness.S"
    harness.write_text(_harness_asm(name_hash, app_data), encoding="utf-8")

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

    elf = tmp_path / "announce_send.elf"
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
            out.extend(emu.read(2048, timeout=0.5))
            if re.search(rb"RET=[0-9a-f]{8}\r\n$", out):
                break
    return bytes(out)


def _parse_ret(output: bytes) -> tuple[int, bytes]:
    marker = b"RET="
    idx = output.rfind(marker)
    assert idx >= 0, output
    ret_hex = output[idx + len(marker):idx + len(marker) + 8]
    assert re.fullmatch(rb"[0-9a-f]{8}", ret_hex), output
    ret_u32 = int(ret_hex, 16)
    ret = ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32
    return ret, output[:idx]


def _assert_trace_lines(prefix: bytes, raw_len: int, kiss_len: int) -> bytes:
    first_fend = prefix.find(bytes([oracle.KISS_FEND]))
    assert first_fend >= 0, prefix

    trace_blob = prefix[:first_fend]
    frame = prefix[first_fend:]
    lines = trace_blob.split(b"\r\n")
    assert lines[-1] == b""
    assert len(lines) == 3, trace_blob
    assert re.fullmatch(
        rb"[0-9a-f]{8}\tannounce\tbuilt\tlen=" + str(raw_len).encode(),
        lines[0],
    )
    assert re.fullmatch(
        rb"[0-9a-f]{8}\tkiss\ttx_frame\tlen=" + str(kiss_len).encode(),
        lines[1],
    )
    return frame


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "announce_send") > 0
    assert build.symbol_address(artifacts.elf, "announce_raw_tx_buf") > 0
    assert build.symbol_address(artifacts.elf, "announce_kiss_tx_buf") > 0


def test_calls_required_components(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="announce_send")
    for callee in ("announce_build", "kiss_encode_frame", "uart_tx_bytes"):
        assert callee in body, f"{callee} not called: {body}"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_announce_send_qemu(tmp_path: Path, case: Case) -> None:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    elf = _build_test_elf(tmp_path, name_hash, case.app_data)

    output = _run_qemu(elf)
    ret, prefix = _parse_ret(output)

    if case.expect_failure:
        assert ret == -1
        assert prefix == b""
        assert oracle.kiss_decode(prefix) == []
        return

    identity, random_hash = _expected_identity_and_random()
    expected = oracle.announce_build(identity, name_hash, random_hash, case.app_data)
    expected_kiss = oracle.kiss_encode(expected.raw_packet)

    assert ret == len(expected.raw_packet) == ANNOUNCE_BASE_RAW_LEN + len(case.app_data)
    frame = _assert_trace_lines(prefix, ret, len(expected_kiss))
    assert frame == expected_kiss
    assert oracle.kiss_decode(frame) == [expected.raw_packet]
    assert oracle.announce_parse(expected.raw_packet) == expected
    assert oracle.announce_validate_pyca(expected.raw_packet)
    if importlib.util.find_spec("RNS") is not None:
        assert oracle.announce_validate_upstream(expected.raw_packet)
