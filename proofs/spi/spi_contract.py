#!/usr/bin/env python3
"""Finite contract/source-shape proof for milestone-8 SPI helpers."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


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
            values[m.group(1)] = int(m.group(2), 0)
    return values


SPI = parse_equ("src/include/spi.S")
OK = SPI["SPI_OK"]
ERR_INVAL = SPI["SPI_ERR_INVAL"]
ERR_OVERFLOW = SPI["SPI_ERR_OVERFLOW"]
ERR_TIMEOUT = SPI["SPI_ERR_TIMEOUT"]
MAX_TRANSFER = SPI["SPI_MAX_TRANSFER"]
CHUNK_BYTES = SPI["SPI_C6_CHUNK_BYTES"]


def transfer_model(
    initialized: bool,
    tx: bytes | None,
    rx_source: bytes | None,
    length: int,
    timeout: int,
    force_timeout: bool = False,
) -> tuple[int, bytes | None, bytes, int]:
    if length == 0:
        return OK, b"" if tx is not None else None, b"", 0
    if length > MAX_TRANSFER:
        return ERR_OVERFLOW, None, b"", 0
    if not initialized or (tx is None and rx_source is None):
        return ERR_INVAL, None, b"", 0
    if timeout == 0 or force_timeout:
        return ERR_TIMEOUT, None, b"", 0

    sent = tx[:length] if tx is not None else bytes(length)
    received = b"" if rx_source is None else rx_source[:length]
    return OK, sent, received, 1


def prove_constants() -> None:
    require((OK, ERR_INVAL, ERR_OVERFLOW, ERR_TIMEOUT) == (0, -1, -2, -3), "status code contract")
    require(MAX_TRANSFER == 256, "SPI transfer bound must match SX1262 FIFO-sized model")
    require(CHUNK_BYTES == 64, "C6 CPU FIFO chunk must use 16 32-bit words")
    require(SPI["SPI_DEFAULT_HZ"] == 1_000_000, "bench clock must default to 1 MHz")
    require(SPI["C6_SPI_CLOCK_1MHZ_XTAL"] == 0x000274E7, "1 MHz XTAL divider mismatch")
    require(SPI["C6_SPI_SCK_PIN"] == 21, "SCK pin contract mismatch")
    require(SPI["C6_SPI_MOSI_PIN"] == 22, "MOSI pin contract mismatch")
    require(SPI["C6_SPI_MISO_PIN"] == 23, "MISO pin contract mismatch")
    require(SPI["C6_FSPICLK_OUT_IDX"] == 63, "FSPI clock signal mismatch")
    require(SPI["C6_FSPIQ_IN_IDX"] == 64, "FSPI MISO signal mismatch")
    require(SPI["C6_FSPID_OUT_IDX"] == 65, "FSPI MOSI signal mismatch")


def prove_finite_model() -> None:
    rx_source = bytes([0xAA, 0xBB, 0xCC, 0xDD])

    rc, sent, received, count_delta = transfer_model(True, bytes([1, 2, 3, 4]), rx_source, 4, 10)
    require(rc == OK and sent == bytes([1, 2, 3, 4]), "full-duplex tx log")
    require(received == rx_source and count_delta == 1, "full-duplex rx/count")

    rc, sent, received, count_delta = transfer_model(True, None, rx_source, 3, 10)
    require(rc == OK and sent == bytes(3), "rx-only transfer must clock zeroes")
    require(received == rx_source[:3] and count_delta == 1, "rx-only receive")

    require(transfer_model(False, b"x", rx_source, 1, 10)[0] == ERR_INVAL, "uninitialized accepted")
    require(transfer_model(True, None, None, 1, 10)[0] == ERR_INVAL, "null tx/rx accepted")
    require(transfer_model(True, b"x", rx_source, MAX_TRANSFER + 1, 10)[0] == ERR_OVERFLOW, "overflow accepted")
    require(transfer_model(True, b"x", rx_source, 1, 0)[0] == ERR_TIMEOUT, "zero timeout accepted")
    require(transfer_model(True, b"x", rx_source, 1, 10, force_timeout=True)[0] == ERR_TIMEOUT, "forced timeout accepted")
    require(transfer_model(False, None, None, 0, 0)[0] == OK, "zero-length no-op rejected")


def require_patterns(path: str, patterns: list[str]) -> None:
    text = read(path)
    for pattern in patterns:
        require(re.search(pattern, text, re.MULTILINE), f"{path}: missing {pattern!r}")


def prove_source_shape() -> None:
    require_patterns("src/interface/spi/spi_init.S", [
        r"C6_PCR_SPI2_CONF",
        r"C6_PCR_SPI2_CLKM_CONF",
        r"C6_SPI2_CLK_GATE",
        r"C6_SPI_CLOCK_1MHZ_XTAL",
        r"C6_SPI_SCK_PIN",
        r"C6_SPI_MOSI_PIN",
        r"C6_SPI_MISO_PIN",
        r"C6_FSPICLK_OUT_IDX",
        r"C6_FSPID_OUT_IDX",
        r"C6_FSPIQ_IN_IDX",
        r"spi_model_initialized",
    ])
    require_patterns("src/interface/spi/spi_transfer.S", [
        r"SPI_MAX_TRANSFER",
        r"SPI_C6_CHUNK_BYTES",
        r"C6_SPI2_W0",
        r"C6_SPI2_MS_DLEN",
        r"C6_SPI_UPDATE",
        r"C6_SPI_USR",
        r"C6_SPI_TRANS_DONE",
        r"spi_model_force_timeout",
        r"spi_model_tx_log",
        r"spi_model_rx_source",
    ])


def main() -> None:
    prove_constants()
    prove_finite_model()
    prove_source_shape()


if __name__ == "__main__":
    main()
