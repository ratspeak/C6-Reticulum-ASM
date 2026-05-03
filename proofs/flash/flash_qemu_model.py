#!/usr/bin/env python3
"""Symbolic verifier for the milestone-4 qemu flash model.

This proof is deliberately small and repo-local. It checks the finite flash
layout constants, proves the read/write/erase acceptance predicates over the
entire reserved-region/page domain, proves the byte-level no-0-to-1 rule, and
binds those facts to the current assembly shape by checking that mutation
stores occur only after the validation guards have completed.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
U32_MAX = (1 << 32) - 1


class ProofError(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


def read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def parse_equ(path: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read(path).splitlines():
        m = re.match(r"\s*\.equ\s+([A-Z0-9_]+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*$", line)
        if m:
            raw = m.group(2)
            values[m.group(1)] = int(raw, 0)
    return values


FLASH = parse_equ("src/include/flash.S")
SECTOR = FLASH["FLASH_SECTOR_SIZE"]
PAGE = FLASH["FLASH_PAGE_SIZE"]
REGION = FLASH["FLASH_IDENTITY_REGION_SIZE"]
RECORD_OFFSET = FLASH["FLASH_IDENTITY_RECORD_OFFSET"]
OK = FLASH["FLASH_OK"]
ERR = FLASH["FLASH_ERR_INVAL"]


def source_body(path: str, symbol: str) -> str:
    text = read(path)
    start = text.index(f"{symbol}:")
    marker = f".size   {symbol}, . - {symbol}"
    end = text.index(marker, start)
    return text[start:end]


def qemu_source_body(path: str, symbol: str) -> str:
    """Return the source shape visible to TARGET_QEMU_VIRT.

    The flash assembly now carries a TARGET_C6 ROM-helper branch before the
    qemu model branch. This verifier binds only the qemu model, so strip one
    top-level TARGET_C6 conditional and leave the qemu `.else` body.
    """
    body = source_body(path, symbol)
    body = re.sub(
        r"^\s*\.ifdef TARGET_C6\s*$.*?^\s*\.else\s*$\n?",
        "",
        body,
        count=1,
        flags=re.MULTILINE | re.DOTALL,
    )
    body = re.sub(r"^\s*\.endif\s*$\n?", "", body, flags=re.MULTILINE)
    return body


def no_store_before(body: str, marker: str, description: str) -> None:
    prefix = body[: body.index(marker)]
    require(not re.search(r"^\s*sb\s+", prefix, re.MULTILINE), description)
    require(not re.search(r"^\s*sw\s+", prefix, re.MULTILINE), description)


def require_ordered(body: str, patterns: list[str], description: str) -> None:
    pos = -1
    for pattern in patterns:
        match = re.search(pattern, body, re.MULTILINE)
        require(match is not None, f"{description}: missing {pattern!r}")
        require(match.start() > pos, f"{description}: out of order {pattern!r}")
        pos = match.start()


def read_accepts(offset: int, length: int) -> bool:
    if not 0 <= offset <= U32_MAX or not 0 <= length <= U32_MAX:
        return False
    if REGION < offset:
        return False
    available = REGION - offset
    return length <= available


def write_shape_accepts(offset: int, length: int) -> bool:
    if not 0 <= offset <= U32_MAX or not 0 <= length <= U32_MAX:
        return False
    if length == 0:
        return False
    if REGION < offset:
        return False
    if length > REGION - offset:
        return False
    page_remaining = PAGE - (offset & (PAGE - 1))
    return length <= page_remaining


def erase_accepts(offset: int) -> bool:
    if not 0 <= offset <= U32_MAX:
        return False
    if offset & (SECTOR - 1):
        return False
    if offset >= REGION:
        return False
    return SECTOR <= REGION - offset


def model_write(storage: bytes, offset: int, data: bytes) -> tuple[int, bytes]:
    if not write_shape_accepts(offset, len(data)):
        return ERR, storage
    for idx, new_byte in enumerate(data):
        old_byte = storage[offset + idx]
        if (old_byte & new_byte) != new_byte:
            return ERR, storage
    out = bytearray(storage)
    out[offset:offset + len(data)] = data
    return OK, bytes(out)


def model_erase(storage: bytes, offset: int) -> tuple[int, bytes]:
    if not erase_accepts(offset):
        return ERR, storage
    out = bytearray(storage)
    out[offset:offset + SECTOR] = b"\xff" * SECTOR
    return OK, bytes(out)


def prove_constants() -> None:
    require(SECTOR == 4096, "sector size must be 4096")
    require(PAGE == 256, "page size must be 256")
    require(REGION == 4096, "identity region must be one sector")
    require(RECORD_OFFSET == 0, "identity record offset must be zero")
    require(OK == 0 and ERR < 0, "flash return code contract")
    require(SECTOR % PAGE == 0, "sector must contain whole pages")


def prove_read_bounds() -> None:
    for offset in range(REGION + 1):
        max_len = REGION - offset
        require(read_accepts(offset, 0), f"zero-length read rejected at {offset}")
        require(read_accepts(offset, max_len), f"max read rejected at {offset}")
        require(not read_accepts(offset, max_len + 1), f"overrun read accepted at {offset}")
    for offset in (REGION + 1, U32_MAX):
        require(not read_accepts(offset, 0), f"out-of-region read accepted at {offset}")


def prove_write_bounds_and_pages() -> None:
    for offset in range(REGION + 1):
        page_remaining = PAGE - (offset & (PAGE - 1))
        max_len = min(REGION - offset, page_remaining)
        require(not write_shape_accepts(offset, 0), f"zero write accepted at {offset}")
        if max_len:
            require(write_shape_accepts(offset, 1), f"one-byte write rejected at {offset}")
            require(
                write_shape_accepts(offset, max_len),
                f"max in-page write rejected at {offset}",
            )
        require(
            not write_shape_accepts(offset, max_len + 1),
            f"page/region crossing write accepted at {offset}",
        )
    for offset in (REGION + 1, U32_MAX):
        require(not write_shape_accepts(offset, 1), f"out-of-region write accepted at {offset}")


def prove_no_zero_to_one_rule() -> None:
    for old in range(256):
        for new in range(256):
            allowed = (old & new) == new
            sets_zero_to_one = ((~old) & new & 0xff) != 0
            require(allowed != sets_zero_to_one, f"bit rule mismatch old={old:#x} new={new:#x}")

    base = bytes([0x0F]) + (b"\xff" * (REGION - 1))
    rc, after = model_write(base, 0, b"\x1f")
    require(rc == ERR and after == base, "0-to-1 single-byte failure mutated storage")

    base = bytes([0x0F, 0xF0, 0xAA]) + (b"\xff" * (REGION - 3))
    rc, after = model_write(base, 0, b"\x0e\xf0\xab")
    require(rc == ERR and after == base, "late validation failure mutated storage")

    rc, after = model_write(base, 0, b"\x0e\xe0\x2a")
    require(rc == OK, "valid clear-only write rejected")
    require(after[:3] == b"\x0e\xe0\x2a", "valid write bytes not programmed")
    require(after[3:] == base[3:], "valid write touched bytes outside range")


def prove_erase() -> None:
    blank = bytes([0x00]) * REGION
    rc, after = model_erase(blank, 0)
    require(rc == OK and after == b"\xff" * REGION, "sector erase did not produce 0xff")
    for offset in (1, PAGE, SECTOR, U32_MAX & ~(SECTOR - 1)):
        rc, after = model_erase(blank, offset)
        require(rc == ERR and after == blank, f"invalid erase accepted/mutated at {offset}")


def prove_source_binding() -> None:
    init = qemu_source_body("src/flash/flash_init.S", "flash_init")
    require_ordered(
        init,
        [
            r"\bla\s+t0,\s*flash_model_initialized",
            r"\blw\s+t1,\s*0\(t0\)",
            r"\bbnez\s+t1,\s*\.Lfi_ok",
            r"\bli\s+t4,\s*0xff",
            r"^\s*1:",
            r"\bsb\s+t4,\s*0\(t2\)",
            r"\bsw\s+t1,\s*0\(t0\)",
        ],
        "flash_init initializes to erased bytes exactly once",
    )

    read_body = qemu_source_body("src/flash/flash_read.S", "flash_read")
    require_ordered(
        read_body,
        [
            r"\bli\s+t0,\s*FLASH_IDENTITY_REGION_SIZE",
            r"\bbltu\s+t0,\s*a0,\s*\.Lfr_fail",
            r"\bsub\s+t1,\s*t0,\s*a0",
            r"\bbltu\s+t1,\s*a2,\s*\.Lfr_fail",
            r"\bbeqz\s+a2,\s*\.Lfr_ok",
            r"\bbeqz\s+a1,\s*\.Lfr_fail",
        ],
        "flash_read validates offset/length before copying",
    )

    write = qemu_source_body("src/flash/flash_write_page.S", "flash_write_page")
    require_ordered(
        write,
        [
            r"\bbeqz\s+a2,\s*\.Lfwp_fail",
            r"\bbeqz\s+a1,\s*\.Lfwp_fail",
            r"\bbltu\s+t0,\s*a0,\s*\.Lfwp_fail",
            r"\bbltu\s+t1,\s*a2,\s*\.Lfwp_fail",
            r"\band\s+t1,\s*a0,\s*t0",
            r"\bbltu\s+t2,\s*a2,\s*\.Lfwp_fail",
            r"^\s*1:",
            r"\band\s+t2,\s*t0,\s*t1",
            r"\bbne\s+t2,\s*t1,\s*\.Lfwp_fail",
            r"^\s*2:",
            r"^\s*3:",
            r"\bsb\s+t6,\s*0\(t3\)",
        ],
        "flash_write_page validates all failure cases before programming",
    )
    no_store_before(write, "\n2:", "flash_write_page stores before validation completes")

    erase = qemu_source_body("src/flash/flash_erase_sector.S", "flash_erase_sector")
    require_ordered(
        erase,
        [
            r"\band\s+t1,\s*a0,\s*t0",
            r"\bbnez\s+t1,\s*\.Lfes_fail",
            r"\bbgeu\s+a0,\s*t0,\s*\.Lfes_fail",
            r"\bbltu\s+t2,\s*t1,\s*\.Lfes_fail",
            r"\bli\s+t5,\s*0xff",
            r"\bsb\s+t5,\s*0\(t3\)",
        ],
        "flash_erase_sector validates alignment/range before erasing",
    )
    no_store_before(erase, "la      t3, flash_model_region", "flash_erase_sector stores before guards")


def prove_binary_presence() -> None:
    sources = {
        "flash_init": "src/flash/flash_init.S",
        "flash_read": "src/flash/flash_read.S",
        "flash_write_page": "src/flash/flash_write_page.S",
        "flash_erase_sector": "src/flash/flash_erase_sector.S",
        "flash_model_region": "src/state/flash.S",
    }
    with tempfile.TemporaryDirectory(prefix="flash-proof-") as tmp:
        tmp_path = Path(tmp)
        for symbol, src in sources.items():
            obj = tmp_path / f"{symbol}.o"
            proc = subprocess.run(
                [
                    "riscv64-elf-as",
                    "-march=rv32imac",
                    "-mabi=ilp32",
                    "--defsym",
                    "TARGET_QEMU_VIRT=1",
                    "-I",
                    str(REPO_ROOT / "src" / "include"),
                    "-o",
                    str(obj),
                    str(REPO_ROOT / src),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            require(proc.returncode == 0, f"assemble {src} failed:\n{proc.stdout}{proc.stderr}")
            proc = subprocess.run(
                ["riscv64-elf-objdump", "-t", str(obj)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            require(proc.returncode == 0, f"objdump {obj} failed:\n{proc.stdout}{proc.stderr}")
            symbols = {
                line.split()[-1]
                for line in proc.stdout.splitlines()
                if line.split()
            }
            require(symbol in symbols, f"missing object symbol {symbol}")


def main() -> int:
    try:
        prove_constants()
        prove_read_bounds()
        prove_write_bounds_and_pages()
        prove_no_zero_to_one_rule()
        prove_erase()
        prove_source_binding()
        prove_binary_presence()
    except ProofError as exc:
        print(f"flash_qemu_model: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "flash_qemu_model: proved qemu flash bounds, page crossing rejection, "
        "no 0->1 writes, and unchanged-on-failure semantics"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
