"""Direct QEMU tests for milestone-6 link_handshake_init."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/link/link_handshake_init.S",
    "src/link/link_request_build.S",
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
    "src/crypto/ed25519/ed25519_field_pow_p5d8.S",
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
    "src/state/link.S",
    "src/state/x25519.S",
    "src/state/ed25519.S",
    "src/state/sha512.S",
    "src/state/rng.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
)

LINK_TABLE_CAPACITY = 4
LINK_ENTRY_SIZE = 296
LINK_TABLE_SIZE = LINK_TABLE_CAPACITY * LINK_ENTRY_SIZE

LE_VALID = 0
LE_STATUS = 1
LE_MODE = 2
LE_RESERVED = 3
LE_LAST_SEEN = 4
LE_DEST_HASH = 8
LE_LOCAL_X25519_PUB = 24
LE_LOCAL_X25519_SK = 56
LE_LOCAL_ED25519_PUB = 88
LE_LOCAL_ED25519_SK = 120
LE_REMOTE_X25519_PUB = 152
LE_REMOTE_ED25519_PUB = 184
LE_LINK_ID = 216
LE_KEY_MATERIAL = 232

LINK_STATUS_PENDING = 1
LINK_MODE_AES256_CBC = 1


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 23) & 0xFF for i in range(length))


DESTS = [_bytes_from(0x10 + i * 17, oracle.DESTINATION_HASH_LEN) for i in range(5)]


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    body: str
    expect_ret: int
    expect_raw: bool = True


def _call(label: str, *, cap: int = oracle.LINK_REQUEST_RAW_LEN, out_null: bool = False) -> str:
    out_arg = "mv      a1, zero" if out_null else "la      a1, raw_out"
    return f"""
        la      a0, {label}
        {out_arg}
        li      a2, {cap}
        call    link_handshake_init
        mv      s11, a0
"""


SCENARIOS = (
    Scenario("single", _call("dest0"), oracle.LINK_REQUEST_RAW_LEN),
    Scenario(
        "duplicate-refresh",
        _call("dest0") + _call("dest0"),
        oracle.LINK_REQUEST_RAW_LEN,
    ),
    Scenario(
        "capacity-evicts-oldest",
        _call("dest0")
        + _call("dest1")
        + _call("dest2")
        + _call("dest3")
        + _call("dest4"),
        oracle.LINK_REQUEST_RAW_LEN,
    ),
    Scenario(
        "overflow-no-side-effect",
        _call("dest0", cap=oracle.LINK_REQUEST_RAW_LEN - 1),
        -2,
        expect_raw=False,
    ),
    Scenario("null-out", _call("dest0", out_null=True), -1, expect_raw=False),
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


def _harness_asm(scenario: Scenario) -> str:
    dest_data = "\n".join(
        f"dest{i}:\n        .byte   {_byte_list(dest)}" for i, dest in enumerate(DESTS)
    )
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
        mv      s11, zero
{scenario.body}

        mv      a0, s11
        call    .Lemit_hex32
        li      a0, 58
        call    .Lputc
        blt     s11, zero, .Lskip_raw
        la      a0, raw_out
        mv      a1, s11
        call    .Lemit_bytes
.Lskip_raw:
        li      a0, 58
        call    .Lputc
        la      a0, link_table
        li      a1, {LINK_TABLE_SIZE}
        call    .Lemit_bytes
        li      a0, 13
        call    .Lputc
        li      a0, 10
        call    .Lputc

.Lhalt:
        wfi
        j       .Lhalt

{_emit_helpers()}

        .global clock_now_ms
        .type   clock_now_ms, @function
clock_now_ms:
        la      t0, fake_now
        lw      a0, 0(t0)
        addi    t1, a0, 10
        sw      t1, 0(t0)
        ret

        .section .data.fake_now, "aw", @progbits
fake_now:
        .word   100

        .section .rodata.dests, "a", @progbits
{dest_data}

        .section .bss.raw_out, "aw", @nobits
        .balign 4
raw_out:
        .skip   {oracle.LINK_REQUEST_RAW_LEN}
"""


def _build_test_elf(tmp_path: Path, scenario: Scenario) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "link_handshake_init_harness.S"
    harness.write_text(_harness_asm(scenario), encoding="utf-8")

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

    elf = tmp_path / "link_handshake_init.elf"
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


def _run_qemu(tmp_path: Path, scenario: Scenario) -> bytes:
    cfg = target.TargetConfig(binary=_build_test_elf(tmp_path, scenario))
    emu = target.EmuTarget(cfg)
    if not emu.is_available():
        pytest.skip("qemu-system-riscv32 not available")

    out = bytearray()
    with emu:
        for _ in range(240):
            out.extend(emu.read(4096, timeout=0.5))
            if out.count(b"\n") >= 1:
                break
    return bytes(out).splitlines()[0]


def _parse_ret(ret_hex: bytes) -> int:
    ret_u32 = int(ret_hex, 16)
    return ret_u32 - (1 << 32) if ret_u32 & 0x80000000 else ret_u32


def _parse_output(line: bytes) -> tuple[int, bytes, bytes]:
    ret_hex, raw_hex, table_hex = line.split(b":")
    ret = _parse_ret(ret_hex)
    raw = bytes.fromhex(raw_hex.decode()) if raw_hex else b""
    table = bytes.fromhex(table_hex.decode()) if table_hex else b""
    assert len(table) == LINK_TABLE_SIZE
    return ret, raw, table


def _entries(table: bytes) -> list[bytes]:
    return [
        table[i * LINK_ENTRY_SIZE:(i + 1) * LINK_ENTRY_SIZE]
        for i in range(LINK_TABLE_CAPACITY)
    ]


def _valid_entries(table: bytes) -> list[bytes]:
    return [entry for entry in _entries(table) if entry[LE_VALID] != 0]


def _dest(entry: bytes) -> bytes:
    return entry[LE_DEST_HASH:LE_DEST_HASH + oracle.DESTINATION_HASH_LEN]


def _local_x25519_pub(entry: bytes) -> bytes:
    return entry[LE_LOCAL_X25519_PUB:LE_LOCAL_X25519_PUB + 32]


def _local_ed25519_pub(entry: bytes) -> bytes:
    return entry[LE_LOCAL_ED25519_PUB:LE_LOCAL_ED25519_PUB + 32]


def _assert_pending_entry(entry: bytes) -> None:
    assert entry[LE_VALID] == 1
    assert entry[LE_STATUS] == LINK_STATUS_PENDING
    assert entry[LE_MODE] == LINK_MODE_AES256_CBC
    assert entry[LE_RESERVED] == 0
    assert any(entry[LE_LOCAL_X25519_PUB:LE_LOCAL_X25519_PUB + 32])
    assert any(entry[LE_LOCAL_X25519_SK:LE_LOCAL_X25519_SK + 32])
    assert any(entry[LE_LOCAL_ED25519_PUB:LE_LOCAL_ED25519_PUB + 32])
    assert any(entry[LE_LOCAL_ED25519_SK:LE_LOCAL_ED25519_SK + 32])
    assert entry[LE_REMOTE_X25519_PUB:LE_KEY_MATERIAL + 64] == bytes(
        LE_KEY_MATERIAL + 64 - LE_REMOTE_X25519_PUB
    )


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_handshake_init") > 0
    assert build.symbol_address(artifacts.elf, "link_table") > 0


def test_calls_expected_dependencies(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_handshake_init")
    for symbol in (
        "clock_now_ms",
        "x25519_keypair",
        "ed25519_keypair",
        "link_request_build",
    ):
        assert symbol in body, body


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[case.name for case in SCENARIOS])
def test_link_handshake_init_qemu(tmp_path: Path, scenario: Scenario) -> None:
    ret, raw, table = _parse_output(_run_qemu(tmp_path, scenario))
    assert ret == scenario.expect_ret
    if not scenario.expect_raw:
        assert raw == b""
        assert _valid_entries(table) == []
        return

    entries = _valid_entries(table)
    if scenario.name == "duplicate-refresh":
        assert len(entries) == 1
    elif scenario.name == "capacity-evicts-oldest":
        assert len(entries) == LINK_TABLE_CAPACITY
        assert DESTS[0] not in {_dest(entry) for entry in entries}
        for dest in DESTS[1:]:
            assert dest in {_dest(entry) for entry in entries}
    else:
        assert len(entries) == 1

    parsed = oracle.link_request_parse(raw)
    matching = [entry for entry in entries if _dest(entry) == parsed.destination_hash]
    assert len(matching) == 1
    entry = matching[0]
    _assert_pending_entry(entry)
    assert _local_x25519_pub(entry) == parsed.x25519_public
    assert _local_ed25519_pub(entry) == parsed.ed25519_public
    assert raw == oracle.link_request_build(
        parsed.destination_hash,
        _local_x25519_pub(entry),
        _local_ed25519_pub(entry),
    ).raw_packet
