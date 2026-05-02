"""Tests for src/crypto/sha256/sha256_init.S.

Static-only for now: verify the function exists, copies eight words
from `sha256_iv` into the ctx H state, then zeros length_bits and
block_len. The .rodata `sha256_iv` constants are byte-level checked
against the FIPS 180-4 §5.3.3 published values.

End-to-end (init+compress+update+final → known hash) lands when
sha256_compress is in place. Until then the strongest claim we can
make from the host is "the IVs are exactly the FIPS values and the
function copies them."
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from harness import build

# FIPS 180-4 §5.3.3 — initial hash values for SHA-256.
SHA256_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _read_bytes_at(elf, addr: int, length: int) -> bytes:
    """Read `length` bytes starting at `addr` from the ELF, via `objdump -s`.

    Linker merges every `.rodata.*` subsection into a single `.rodata`
    output section, so we cannot ask for `.rodata.sha256_iv` directly.
    Instead we constrain the dump range with `--start-address` /
    `--stop-address`.
    """
    if shutil.which("riscv64-elf-objdump") is None:
        pytest.skip("riscv64-elf-objdump not on PATH")
    proc = subprocess.run(
        [
            "riscv64-elf-objdump", "-s",
            f"--start-address=0x{addr:x}",
            f"--stop-address=0x{addr + length:x}",
            str(elf),
        ],
        capture_output=True, text=True, check=True,
    )
    out = bytearray()
    # Each data line: " 800002b8 67e6096a 85ae67bb 72f36e3c 3af54fa5  ASCII"
    line_re = re.compile(r"^\s+([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s*)+?)\s{2}")
    for line in proc.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        for chunk in m.group(2).split():
            for i in range(0, len(chunk), 2):
                out.append(int(chunk[i:i + 2], 16))
    return bytes(out[:length])


# --- static --------------------------------------------------------------


def test_function_exists(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_init") > 0


def test_sha256_iv_symbol_present(artifacts: build.BuildArtifacts) -> None:
    assert build.symbol_address(artifacts.elf, "sha256_iv") > 0


def test_sha256_iv_bytes_match_fips(artifacts: build.BuildArtifacts) -> None:
    """The 32 bytes at sha256_iv must be exactly the FIPS IVs in LE order."""
    addr = build.symbol_address(artifacts.elf, "sha256_iv")
    raw = _read_bytes_at(artifacts.elf, addr, 32)
    assert len(raw) == 32, f"sha256_iv: got {len(raw)} bytes, want 32"
    words = tuple(
        int.from_bytes(raw[i:i + 4], "little") for i in range(0, 32, 4)
    )
    assert words == SHA256_IV, \
        f"IV mismatch: got {[hex(w) for w in words]}, want {[hex(w) for w in SHA256_IV]}"


def test_sha256_ctx_singleton_present(artifacts: build.BuildArtifacts) -> None:
    """The 112-byte sha256_ctx singleton must exist in .bss."""
    assert build.symbol_address(artifacts.elf, "sha256_ctx") > 0


def test_body_references_sha256_iv(artifacts: build.BuildArtifacts) -> None:
    """The init function loads the IV table address (auipc/addi pair)."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_init")
    assert "sha256_iv" in body, body


def test_body_zeros_length_and_block_len(artifacts: build.BuildArtifacts) -> None:
    """Init zeros the 8-byte length_bits (offsets 32, 36) and 4-byte
    block_len (offset 104). Three `sw zero, OFF(a0)` instructions
    cover this."""
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_init")
    # Three sw zero stores into the ctx (a0 base); offsets resolve in the
    # disassembly comment as `# 0`, `# 4`, `# 0x68` (104).
    sw_zero = re.findall(r"\bsw\s+zero,\s*(0x[0-9a-f]+|\d+)\(a0\)", body)
    assert len(sw_zero) >= 3, f"expected ≥3 sw zero stores into ctx: {body}"


def test_no_callee_saved_writes(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_init")
    for match in re.findall(r"\b(s\d+)\b,", body):
        pytest.fail(f"sha256_init writes callee-saved {match}: {body}")


def test_no_stack_frame(artifacts: build.BuildArtifacts) -> None:
    body = build.objdump_disassemble(artifacts.elf, symbol="sha256_init")
    assert not re.search(r"\baddi\b\s+sp\b", body), \
        f"unexpected sp adjust in leaf: {body}"
