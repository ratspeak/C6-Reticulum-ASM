"""Direct QEMU tests for milestone-6 link_handshake_accept."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import build, oracle, target

REPO_ROOT = Path(__file__).resolve().parents[2]

ASM_SOURCES = (
    "src/link/link_handshake_accept.S",
    "src/link/link_request_parse.S",
    "src/link/link_derive_keys.S",
    "src/packet/packet_parse_header.S",
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
    "src/crypto/rng/rng_init.S",
    "src/crypto/rng/rng_entropy.S",
    "src/crypto/rng/rng_bytes.S",
    "src/crypto/rng/hmac_drbg_update.S",
    "src/crypto/hkdf/hkdf_extract.S",
    "src/crypto/hkdf/hkdf_expand.S",
    "src/crypto/hmac/hmac_sha256.S",
    "src/crypto/sha256/sha256_init.S",
    "src/crypto/sha256/sha256_update.S",
    "src/crypto/sha256/sha256_final.S",
    "src/crypto/sha256/sha256_compress.S",
    "src/state/link.S",
    "src/state/x25519.S",
    "src/state/rng.S",
    "src/state/hkdf.S",
    "src/state/hmac.S",
    "src/state/sha256.S",
)

LINK_TABLE_CAPACITY = 4
LINK_ENTRY_SIZE = 296
LINK_TABLE_SIZE = LINK_TABLE_CAPACITY * LINK_ENTRY_SIZE
LINK_REQUEST_T_SIZE = 92

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

LINK_STATUS_ESTABLISHED = 2
LINK_MODE_AES256_CBC = 1
LINK_STATUS_DUPLICATE = 1


def _bytes_from(seed: int, length: int) -> bytes:
    return bytes((seed + i * 29) & 0xFF for i in range(length))


REMOTE_IDENTITIES = [
    oracle.identity_from_private_parts(_bytes_from(0x11 + i * 7, 32), _bytes_from(0x80 + i * 9, 32))
    for i in range(5)
]
DESTS = [_bytes_from(0x30 + i * 13, oracle.DESTINATION_HASH_LEN) for i in range(5)]
REQUESTS = [
    oracle.link_request_build(dest, ident.x25519_public, ident.ed25519_public).raw_packet
    for dest, ident in zip(DESTS, REMOTE_IDENTITIES, strict=True)
]
REQUEST_SAME_DEST_NEW_REMOTE = oracle.link_request_build(
    DESTS[0],
    REMOTE_IDENTITIES[1].x25519_public,
    REMOTE_IDENTITIES[1].ed25519_public,
).raw_packet


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    body: str
    expect_ret: int
    expect_count: int
    expected_dests: tuple[bytes, ...]
    expected_raw: bytes | None = None


def _parse_and_accept(label: str, parsed_label: str = "parsed") -> str:
    return f"""
        la      a0, {label}
        li      a1, {oracle.LINK_REQUEST_RAW_LEN}
        la      a2, {parsed_label}
        call    link_request_parse
        mv      s11, a0
        bnez    s11, 1f
        la      a0, {parsed_label}
        call    link_handshake_accept
        mv      s11, a0
1:
"""


def _invalid_parsed_call() -> str:
    return """
        la      a0, parsed
        sw      zero, 0(a0)
        call    link_handshake_accept
        mv      s11, a0
"""


SCENARIOS = (
    Scenario("accept-new", _parse_and_accept("request0"), 0, 1, (DESTS[0],), REQUESTS[0]),
    Scenario(
        "duplicate",
        _parse_and_accept("request0") + _parse_and_accept("request0"),
        LINK_STATUS_DUPLICATE,
        1,
        (DESTS[0],),
        REQUESTS[0],
    ),
    Scenario(
        "same-dest-new-remote-replaces",
        _parse_and_accept("request0") + _parse_and_accept("request_same_dest_new_remote"),
        0,
        1,
        (DESTS[0],),
        REQUEST_SAME_DEST_NEW_REMOTE,
    ),
    Scenario(
        "capacity-evicts-oldest",
        _parse_and_accept("request0")
        + _parse_and_accept("request1")
        + _parse_and_accept("request2")
        + _parse_and_accept("request3")
        + _parse_and_accept("request4"),
        0,
        4,
        tuple(DESTS[1:]),
        REQUESTS[4],
    ),
    Scenario("invalid-parsed", _invalid_parsed_call(), -1, 0, ()),
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
    request_data = "\n".join(
        f"request{i}:\n        .byte   {_byte_list(raw)}" for i, raw in enumerate(REQUESTS)
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

        .section .rodata.requests, "a", @progbits
{request_data}
request_same_dest_new_remote:
        .byte   {_byte_list(REQUEST_SAME_DEST_NEW_REMOTE)}

        .section .bss.parsed, "aw", @nobits
        .balign 4
parsed:
        .skip   {LINK_REQUEST_T_SIZE}
"""


def _build_test_elf(tmp_path: Path, scenario: Scenario) -> Path:
    as_bin = _require_tool("riscv64-elf-as")
    ld_bin = _require_tool("riscv64-elf-ld")

    harness = tmp_path / "link_handshake_accept_harness.S"
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

    elf = tmp_path / "link_handshake_accept.elf"
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


def _parse_output(line: bytes) -> tuple[int, bytes]:
    ret_hex, table_hex = line.split(b":")
    ret = _parse_ret(ret_hex)
    table = bytes.fromhex(table_hex.decode()) if table_hex else b""
    assert len(table) == LINK_TABLE_SIZE
    return ret, table


def _entries(table: bytes) -> list[bytes]:
    return [
        table[i * LINK_ENTRY_SIZE:(i + 1) * LINK_ENTRY_SIZE]
        for i in range(LINK_TABLE_CAPACITY)
    ]


def _valid_entries(table: bytes) -> list[bytes]:
    return [entry for entry in _entries(table) if entry[LE_VALID] != 0]


def _dest(entry: bytes) -> bytes:
    return entry[LE_DEST_HASH:LE_DEST_HASH + 16]


def _link_id(raw: bytes) -> bytes:
    hashable = bytes([raw[0] & 0x0F]) + raw[2:-3]
    return hashlib.sha256(hashable).digest()[:16]


def _hkdf(shared_secret: bytes, salt: bytes, length: int = 64) -> bytes:
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    block = b""
    out = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _shared_secret(local_sk: bytes, remote_x25519_pub: bytes) -> bytes:
    x25519, _ed25519, _ser, _invalid = oracle._require_pyca()
    private = x25519.X25519PrivateKey.from_private_bytes(local_sk)
    public = x25519.X25519PublicKey.from_public_bytes(remote_x25519_pub)
    return private.exchange(public)


def _assert_established(entry: bytes, raw_request: bytes) -> None:
    parsed = oracle.link_request_parse(raw_request)
    assert entry[LE_VALID] == 1
    assert entry[LE_STATUS] == LINK_STATUS_ESTABLISHED
    assert entry[LE_MODE] == LINK_MODE_AES256_CBC
    assert entry[LE_RESERVED] == 0
    assert _dest(entry) == parsed.destination_hash
    assert entry[LE_REMOTE_X25519_PUB:LE_REMOTE_X25519_PUB + 32] == parsed.x25519_public
    assert entry[LE_REMOTE_ED25519_PUB:LE_REMOTE_ED25519_PUB + 32] == parsed.ed25519_public
    assert any(entry[LE_LOCAL_X25519_PUB:LE_LOCAL_X25519_PUB + 32])
    assert any(entry[LE_LOCAL_X25519_SK:LE_LOCAL_X25519_SK + 32])
    assert entry[LE_LOCAL_ED25519_PUB:LE_REMOTE_X25519_PUB] == bytes(
        LE_REMOTE_X25519_PUB - LE_LOCAL_ED25519_PUB
    )
    expected_link_id = _link_id(raw_request)
    assert entry[LE_LINK_ID:LE_LINK_ID + 16] == expected_link_id
    shared = _shared_secret(
        entry[LE_LOCAL_X25519_SK:LE_LOCAL_X25519_SK + 32],
        parsed.x25519_public,
    )
    assert entry[LE_KEY_MATERIAL:LE_KEY_MATERIAL + 64] == _hkdf(shared, expected_link_id)


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "link_handshake_accept") > 0


def test_calls_expected_dependencies(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="link_handshake_accept")
    for symbol in (
        "clock_now_ms",
        "x25519_keypair",
        "x25519_scalar_mult",
        "sha256_init",
        "sha256_update",
        "sha256_final",
        "link_derive_keys",
    ):
        assert symbol in body, body


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[case.name for case in SCENARIOS])
def test_link_handshake_accept_qemu(tmp_path: Path, scenario: Scenario) -> None:
    ret, table = _parse_output(_run_qemu(tmp_path, scenario))
    assert ret == scenario.expect_ret
    entries = _valid_entries(table)
    assert len(entries) == scenario.expect_count
    assert {_dest(entry) for entry in entries} == set(scenario.expected_dests)
    if scenario.expected_raw is not None:
        matching = [
            entry
            for entry in entries
            if _dest(entry) == oracle.link_request_parse(scenario.expected_raw).destination_hash
        ]
        assert len(matching) == 1
        _assert_established(matching[0], scenario.expected_raw)
