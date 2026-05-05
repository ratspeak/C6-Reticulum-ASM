"""Direct QEMU tests for src/transport/transport_process_announce.S."""

from __future__ import annotations

import dataclasses
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/transport/transport_process_announce.S",
    "src/transport/transport_path_init.S",
    "src/transport/transport_path_update.S",
    "src/transport/transport_path_lookup.S",
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
    "src/state/transport.S",
    "src/state/ed25519.S",
    "src/state/sha512.S",
    "src/state/sha256.S",
)

TP_VALID = 0
TP_INTERFACE = 1
TP_HOPS = 2
TP_LAST_SEEN = 4
TP_DEST_HASH = 8
TP_IDENTITY_HASH = 24
TP_PUBLIC_KEY = 40
TP_ENTRY_SIZE = 104


@dataclasses.dataclass(frozen=True)
class PacketCase:
    raw0: bytes
    raw1: bytes
    bad: bytes


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


def _packet(app_data: bytes, random_seed: int, hops: int) -> bytes:
    pytest.importorskip("cryptography", reason="pyca required for announce oracle")
    identity = oracle.identity_from_private_parts(bytes(range(32)), bytes(range(32, 64)))
    name_hash = oracle.destination_name_hash_from_parts("rnstransport", "nodes")
    random_hash = bytes((random_seed + i) & 0xFF for i in range(10))
    raw = bytearray(oracle.announce_build(identity, name_hash, random_hash, app_data).raw_packet)
    raw[1] = hops & 0xFF
    return bytes(raw)


def _packets() -> PacketCase:
    raw0 = _packet(b"first", 0x10, hops=7)
    raw1 = _packet(b"second", 0x20, hops=9)
    bad = bytearray(raw0)
    bad[-1] ^= 0x01
    return PacketCase(raw0=raw0, raw1=raw1, bad=bytes(bad))


def _emit_process(label: str, length: int, interface_id: int = 1) -> str:
    return f"""
        la      a0, {label}
        li      a1, {length}
        li      a2, {interface_id}
        call    transport_process_announce
        call    .Lemit_hex32_line
"""


def _emit_lookup(label: str) -> str:
    return f"""
        la      a0, {label}
        addi    a0, a0, 2
        la      a1, out_entry
        call    transport_path_lookup
        la      a1, out_entry
        li      a2, {TP_ENTRY_SIZE}
        call    .Lemit_ret_bytes
"""


def _harness_asm(packets: PacketCase, body: str) -> str:
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

.Lhalt:
        wfi
        j       .Lhalt

.Lemit_ret_bytes:
        addi    sp, sp, -16
        sw      s0, 0(sp)
        sw      s1, 4(sp)
        sw      ra, 12(sp)
        mv      s0, a1
        mv      s1, a2
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        mv      a0, s0
        mv      a1, s1
        call    .Lemit_bytes
        call    .Lnewline
        lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lemit_hex32_line:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        call    .Lemit_hex32
        call    .Lnewline
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

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

.Lnewline:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

.Lputc:
        li      t0, 0x10000000
5:      lbu     t1, 5(t0)
        andi    t1, t1, 0x20
        beqz    t1, 5b
        sb      a0, 0(t0)
        ret

        .global clock_now_ms
        .type   clock_now_ms, @function
clock_now_ms:
        la      t0, fake_now
        lw      a0, 0(t0)
        addi    t1, a0, 10
        sw      t1, 0(t0)
        ret

        .size   _reset, . - _reset

        .section .data.raw_packets, "aw", @progbits
        .balign 4
raw0:
        .byte   {_byte_list(packets.raw0)}
        .balign 4
raw1:
        .byte   {_byte_list(packets.raw1)}
        .balign 4
bad_raw:
        .byte   {_byte_list(packets.bad)}
fake_now:
        .word   100

        .section .bss.out_entry, "aw", @nobits
        .balign 4
out_entry:
        .skip   {TP_ENTRY_SIZE}
"""


def _build_test_elf(tmp_path: Path, packets: PacketCase, body: str) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "transport_process_harness.S"
    harness.write_text(_harness_asm(packets, body), encoding="utf-8")

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

    elf = tmp_path / "transport_process.elf"
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


def _run_qemu(tmp_path: Path, packets: PacketCase, body: str, line_count: int) -> list[bytes]:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, packets, body))
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(240):
            out.extend(emu.read(2048, timeout=0.5))
            if out.count(b"\n") >= line_count:
                break
    return bytes(out).splitlines()[:line_count]


def _signed_hex(line: bytes) -> int:
    value = int(line, 16)
    return value - (1 << 32) if value & 0x80000000 else value


def _parse_ret_entry(line: bytes) -> tuple[int, bytes]:
    ret_hex, _, entry_hex = line.partition(b":")
    return _signed_hex(ret_hex), bytes.fromhex(entry_hex.decode())


def _entry_fields(entry: bytes) -> dict[str, bytes | int]:
    return {
        "valid": entry[TP_VALID],
        "interface": entry[TP_INTERFACE],
        "hops": entry[TP_HOPS],
        "last_seen": struct.unpack_from("<I", entry, TP_LAST_SEEN)[0],
        "dest_hash": entry[TP_DEST_HASH:TP_DEST_HASH + 16],
        "identity_hash": entry[TP_IDENTITY_HASH:TP_IDENTITY_HASH + 16],
        "public_key": entry[TP_PUBLIC_KEY:TP_PUBLIC_KEY + 64],
    }


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "transport_process_announce") > 0


def test_static_calls_required_components(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="transport_process_announce")
    for callee in (
        "announce_parse",
        "announce_validate",
        "transport_path_lookup",
        "transport_path_update",
    ):
        assert callee in body


def test_process_valid_new_announce(tmp_path: Path) -> None:
    packets = _packets()
    body = f"""
        call    transport_path_init
{_emit_process("raw0", len(packets.raw0))}
{_emit_lookup("raw0")}
"""
    ret_line, lookup_line = _run_qemu(tmp_path, packets, body, line_count=2)
    lookup_ret, entry = _parse_ret_entry(lookup_line)
    fields = _entry_fields(entry)
    parsed = oracle.announce_parse(packets.raw0)

    assert _signed_hex(ret_line) == 0
    assert lookup_ret == 0
    assert fields["valid"] == 1
    assert fields["interface"] == 1
    assert fields["hops"] == 8
    assert fields["last_seen"] == 100
    assert fields["dest_hash"] == parsed.destination_hash
    assert fields["identity_hash"] == oracle.identity_hash(parsed.public_key)
    assert fields["public_key"] == parsed.public_key


def test_process_duplicate_returns_update_status(tmp_path: Path) -> None:
    packets = _packets()
    body = f"""
        call    transport_path_init
{_emit_process("raw0", len(packets.raw0))}
{_emit_process("raw1", len(packets.raw1))}
{_emit_lookup("raw0")}
"""
    first_line, second_line, lookup_line = _run_qemu(tmp_path, packets, body, line_count=3)
    lookup_ret, entry = _parse_ret_entry(lookup_line)
    fields = _entry_fields(entry)

    assert _signed_hex(first_line) == 0
    assert _signed_hex(second_line) == 1
    assert lookup_ret == 0
    assert fields["hops"] == 10
    assert fields["last_seen"] == 110


def test_process_invalid_announce_does_not_update_table(tmp_path: Path) -> None:
    packets = _packets()
    body = f"""
        call    transport_path_init
{_emit_process("bad_raw", len(packets.bad))}
{_emit_lookup("bad_raw")}
"""
    ret_line, lookup_line = _run_qemu(tmp_path, packets, body, line_count=2)
    lookup_ret, _entry = _parse_ret_entry(lookup_line)
    assert _signed_hex(ret_line) == -1
    assert lookup_ret == -2


def test_process_rejects_invalid_interface(tmp_path: Path) -> None:
    packets = _packets()
    body = f"""
        call    transport_path_init
{_emit_process("raw0", len(packets.raw0), interface_id=0)}
{_emit_lookup("raw0")}
"""
    ret_line, lookup_line = _run_qemu(tmp_path, packets, body, line_count=2)
    lookup_ret, _entry = _parse_ret_entry(lookup_line)
    assert _signed_hex(ret_line) == -1
    assert lookup_ret == -2
