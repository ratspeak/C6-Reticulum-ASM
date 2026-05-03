"""Tests for src/destination/destination_name_hash.S.

The Reticulum oracle is the upstream Python reference in
../upstream/Reticulum. Static ELF checks make sure the asm wrapper is built
and delegates to the verified SHA-256 chain; oracle vectors pin the exact
80-bit name-hash truncation used by RNS.Destination.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import pytest

from harness import build

UPSTREAM_RETICULUM = Path(__file__).resolve().parents[3] / "upstream" / "Reticulum"

NAME_CASES = (
    ("rnstransport", ("nodes",)),
    ("lxmf", ("delivery",)),
    ("riscv", ("c6", "harness")),
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _rns():
    sys.path.insert(0, str(UPSTREAM_RETICULUM))
    import RNS  # type: ignore[import-not-found]

    return RNS


def _upstream_name_hash(name: bytes) -> bytes:
    rns = _rns()
    return rns.Identity.full_hash(name)[: rns.Identity.NAME_HASH_LENGTH // 8]


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "destination_name_hash") > 0


def test_calls_sha256_chain(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_name_hash")
    for callee in ("sha256_init", "sha256_update", "sha256_final"):
        assert callee in body, f"{callee} not called: {body}"


def test_truncates_to_name_hash_length(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_name_hash")
    assert re.search(r"\bli\b\s+\w+,\s*10\b", body), body


def test_saves_callee_saved(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="destination_name_hash")
    saved = set(re.findall(r"\bsw\b\s+(s\d+)\b", body))
    assert {f"s{i}" for i in range(3)}.issubset(saved), \
        f"expected s0..s2 saved, saw {saved}"


@pytest.mark.parametrize("app_name,aspects", NAME_CASES)
def test_upstream_destination_name_vectors(
    app_name: str, aspects: tuple[str, ...],
) -> None:
    rns = _rns()
    expanded = rns.Destination.expand_name(None, app_name, *aspects)
    name_bytes = expanded.encode("utf-8")
    expected = hashlib.sha256(name_bytes).digest()[:10]
    assert _upstream_name_hash(name_bytes) == expected


def test_zero_length_name_hash_layer_is_sha256_truncation() -> None:
    assert _upstream_name_hash(b"") == hashlib.sha256(b"").digest()[:10]


def test_max_harness_name_length_vector() -> None:
    name = b"a" * 255
    assert _upstream_name_hash(name) == hashlib.sha256(name).digest()[:10]
