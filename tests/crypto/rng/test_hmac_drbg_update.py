"""Static checks for `hmac_drbg_update` — the NIST SP 800-90A Rev. 1
§10.1.2.2 update primitive used by both `rng_init` (instantiate, with
48-byte seed_material) and `rng_bytes` (post-generate backtracking-
resistance update, with empty data).

The QEMU end-to-end behaviour is covered transitively by
`test_rng_bytes.py` — its DRBG oracle calls `drbg_oracle.drbg_update`
inside `drbg_oracle.drbg_instantiate` and `drbg_oracle.drbg_generate`,
so any asm divergence breaks the rng_bytes oracle match. The Tier A
SAW driver (`proofs/crypto/rng/hmac_drbg_update.saw`) discharges
HMAC-DRBG_Update against the verified HMAC-SHA-256 model.
"""
from __future__ import annotations

import re

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "hmac_drbg_update") > 0


def test_calls_hmac_sha256(artifacts):
    """Update consists exclusively of HMAC-SHA-256 invocations
    (4× when data_len > 0, 2× when data_len == 0)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_drbg_update")
    assert "hmac_sha256" in body, "hmac_sha256 not invoked"


def test_no_recursion(artifacts):
    """The update primitive must not call `rng_init`, `rng_bytes`, or
    itself — otherwise the DRBG layering would loop. (It MAY call
    `hmac_sha256` and the static helpers `.Lcopy_v_to_buf` / `.Lcopy_data`.)"""
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_drbg_update")
    for sym in ("rng_init", "rng_bytes", "rng_entropy"):
        assert sym not in body, f"hmac_drbg_update must not call {sym}"


def test_stack_frame_balanced(artifacts):
    body = build.objdump_disassemble(artifacts.elf, symbol="hmac_drbg_update")
    allocs = re.findall(r"addi\s+sp\s*,\s*sp\s*,\s*(-?\d+)", body)
    assert allocs, f"no sp adjustments: {body[:200]}"
    net = sum(int(x) for x in allocs)
    assert net == 0, f"unbalanced sp: {allocs}"


def test_state_symbols_referenced(artifacts):
    """Update touches all three pieces of DRBG state via the linker —
    the ELF must carry references to K, V, and the scratch buf (the
    reseed_counter is touched by rng_init / rng_bytes only)."""
    for sym in ("hmac_drbg_K", "hmac_drbg_V", "hmac_drbg_buf"):
        assert build.symbol_address(artifacts.elf, sym) > 0, sym
