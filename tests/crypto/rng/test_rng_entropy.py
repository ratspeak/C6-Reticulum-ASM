"""Static checks for `rng_entropy` (the raw entropy source under the
HMAC-DRBG layer).

The QEMU end-to-end behaviour is covered transitively by
`test_rng_bytes.py` — its DRBG oracle invokes
`drbg_oracle.entropy(48, counter_start=0)` to predict the seed_material
that `rng_init`'s `rng_entropy` call materialises, so any divergence
between the asm `rng_entropy` and `sha256(SEED || counter_le32)` would
break that test. We add static checks here for symbol presence and
the expected dispatch on TARGET_QEMU_VIRT vs TARGET_C6 (the hardware
demo `tests/hardware/test_rng.py` does the live HW path)."""
from __future__ import annotations

import pytest

from harness import build


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "rng_entropy") > 0


def test_qemu_path_uses_sha256(artifacts):
    """On TARGET_QEMU_VIRT the deterministic-fake CSPRNG body calls
    sha256_init/update/final to compute one block per loop iteration."""
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_entropy")
    for sym in ("sha256_init", "sha256_update", "sha256_final"):
        assert sym in body, f"{sym} not invoked from rng_entropy on qemu"


def test_seed_symbol_present(artifacts):
    """The DETERMINISTIC_FAKE_RNG marker must remain in the qemu-virt
    ELF — the CI release-build gate refuses any image that links it."""
    assert build.symbol_address(artifacts.elf, "DETERMINISTIC_FAKE_RNG") > 0


def test_no_drbg_dependency(artifacts):
    """rng_entropy must be a pure entropy source — never call back
    into the DRBG layer (rng_init / rng_bytes / hmac_drbg_update),
    otherwise the layering would loop."""
    body = build.objdump_disassemble(artifacts.elf, symbol="rng_entropy")
    for sym in ("rng_init", "rng_bytes", "hmac_drbg_update"):
        assert sym not in body, f"rng_entropy must not call {sym}"
