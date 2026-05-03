"""Build-system helpers for tests that need the firmware ELF.

The first time a test asks for the ELF, we shell out to `make build` and
cache the resulting path. Subsequent calls in the same pytest session
reuse the cached path without rebuilding.

This is intentionally not a fixture: most tests want a path string, and
exposing a bare function avoids fixture-scope plumbing through every test.
"""

from __future__ import annotations

import dataclasses
import functools
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclasses.dataclass(frozen=True)
class BuildArtifacts:
    target: str
    elf: Path
    bin: Path
    build_dir: Path
    # ESP-image-format .bin produced by `make image` for TARGET=c6 (the file
    # the mask-ROM second-stage loader consumes from flash offset 0x0).
    # `None` for qemu-virt where the toolchain emits a flat .bin loaded
    # straight by qemu's `-kernel` flag.
    image_bin: Path | None = None


class BuildError(RuntimeError):
    """Raised when `make build` fails."""


def _toolchain_present() -> bool:
    return all(
        shutil.which(t) is not None
        for t in ("riscv64-elf-as", "riscv64-elf-ld", "riscv64-elf-objcopy")
    )


@functools.lru_cache(maxsize=4)
def build(target: str = "qemu-virt", *, force: bool = False) -> BuildArtifacts:
    """Run `make build TARGET=<target>` and return the artifact paths.

    Cached by target. Pass `force=True` to re-run (rare; mostly for tests
    that change source between cases).
    """
    if not _toolchain_present():
        raise BuildError(
            "riscv64-elf-binutils not on PATH; "
            "install via `brew install riscv64-elf-binutils`"
        )
    cmd = ["make", "build", f"TARGET={target}"]
    if force:
        # Make rebuild conditional: clean only the per-target tree.
        subprocess.run(
            ["rm", "-rf", str(REPO_ROOT / "build" / target)], check=True
        )
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise BuildError(
            f"make build TARGET={target} failed (exit {proc.returncode}):\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    build_dir = REPO_ROOT / "build" / target
    elf = build_dir / "firmware.elf"
    binp = build_dir / "firmware.bin"
    if not elf.exists():
        raise BuildError(f"build succeeded but {elf} not produced")

    image_bin: Path | None = None
    if target == "c6":
        # Run `make image TARGET=c6` to produce the ESP-format .image.bin
        # the mask-ROM second-stage loader consumes from flash 0x0. Cheap
        # to re-run (esptool elf2image on a 30 KB ELF is sub-second), and
        # always running it keeps the artifact in sync with the ELF when a
        # test forces a rebuild via `force=True`.
        image_proc = subprocess.run(
            ["make", "image", f"TARGET={target}"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if image_proc.returncode != 0:
            raise BuildError(
                f"make image TARGET={target} failed (exit {image_proc.returncode}):\n"
                f"{image_proc.stdout}\n{image_proc.stderr}"
            )
        image_bin = build_dir / "firmware.image.bin"
        if not image_bin.exists():
            raise BuildError(f"make image succeeded but {image_bin} not produced")

    return BuildArtifacts(
        target=target, elf=elf, bin=binp, build_dir=build_dir, image_bin=image_bin,
    )


def objdump_disassemble(elf: Path, *, symbol: str | None = None) -> str:
    """Return the disassembly text from objdump. Optionally restrict to one
    symbol's body (useful for asserting on the prologue of a single function).
    """
    if shutil.which("riscv64-elf-objdump") is None:
        raise BuildError("riscv64-elf-objdump not on PATH")
    proc = subprocess.run(
        ["riscv64-elf-objdump", "-d", str(elf)],
        capture_output=True, text=True, check=True,
    )
    if symbol is None:
        return proc.stdout
    # Crude slice: from "<symbol>:" to next blank line. Good enough for the
    # tiny boot stubs we have today; refine later if a function gets long.
    text = proc.stdout
    marker = f"<{symbol}>:"
    idx = text.find(marker)
    if idx < 0:
        raise BuildError(f"symbol {symbol!r} not found in {elf}")
    rest = text[idx:]
    end = rest.find("\n\n")
    return rest if end < 0 else rest[:end]


def objdump_entry_point(elf: Path) -> int:
    """Return the ELF entry-point address."""
    if shutil.which("riscv64-elf-objdump") is None:
        raise BuildError("riscv64-elf-objdump not on PATH")
    proc = subprocess.run(
        ["riscv64-elf-objdump", "-f", str(elf)],
        capture_output=True, text=True, check=True,
    )
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("start address"):
            return int(line.split()[-1], 16)
    raise BuildError(f"no 'start address' in objdump -f for {elf}")


def symbol_address(elf: Path, name: str) -> int:
    """Return the address of a symbol from `objdump -t` output.

    Function lines have 6 fields (`addr flags F section size name`); data
    lines (BSS/.rodata globals) have 5 (no F flag). We accept either.
    """
    if shutil.which("riscv64-elf-objdump") is None:
        raise BuildError("riscv64-elf-objdump not on PATH")
    proc = subprocess.run(
        ["riscv64-elf-objdump", "-t", str(elf)],
        capture_output=True, text=True, check=True,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == name:
            return int(parts[0], 16)
    raise BuildError(f"symbol {name!r} not found in {elf}")
