"""Tests for src/destination/destination_hash.S.

The byte oracle is upstream RNS.Destination.hash(identity_hash, app, *aspects)
with identity supplied as the 16-byte Reticulum identity hash form.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import pytest

from harness import build

UPSTREAM_RETICULUM = Path(__file__).resolve().parents[3] / "upstream" / "Reticulum"

DESTINATION_CASES = (
    ("rnstransport", ("nodes",), bytes(range(16))),
    (
        "lxmf",
        ("delivery",),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ),
    (
        "riscv",
        ("c6", "harness"),
        bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
    ),
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _rns():
    sys.path.insert(0, str(UPSTREAM_RETICULUM))
    import RNS  # type: ignore[import-not-found]

    return RNS


def _name_hash(app_name: str, aspects: tuple[str, ...]) -> bytes:
    rns = _rns()
    expanded = rns.Destination.expand_name(None, app_name, *aspects)
    return rns.Identity.full_hash(expanded.encode("utf-8"))[
        : rns.Identity.NAME_HASH_LENGTH // 8
    ]


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "destination_hash") > 0


def test_calls_sha256_chain(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    assert "sha256_init" in body, body
    assert body.count("sha256_update") >= 2, body
    assert "sha256_final" in body, body


def test_uses_reticulum_hash_lengths(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    for length in (10, 16):
        assert re.search(rf"\bli\b\s+\w+,\s*{length}\b", body), body


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_hash")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(3)}.issubset(saved), \
        f"expected s0..s2 saved, saw {saved}"


@pytest.mark.parametrize("app_name,aspects,identity_hash", DESTINATION_CASES)
def test_upstream_destination_hash_vectors(
    app_name: str, aspects: tuple[str, ...], identity_hash: bytes,
) -> None:
    rns = _rns()
    name_hash = _name_hash(app_name, aspects)
    expected = hashlib.sha256(name_hash + identity_hash).digest()[:16]
    assert rns.Destination.hash(identity_hash, app_name, *aspects) == expected


def test_zero_length_name_hash_layer_vector() -> None:
    identity_hash = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    name_hash = hashlib.sha256(b"").digest()[:10]
    expected = hashlib.sha256(name_hash + identity_hash).digest()[:16]
    assert expected.hex() == "9c4a69a5f50a9c8e7b385fd7abfd0ddc"
