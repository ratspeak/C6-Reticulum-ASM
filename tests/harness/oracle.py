"""Oracle wrappers around the upstream Python Reticulum reference (ADR-0005,
the `oracle` target).

For functions that have a reference implementation in upstream Python, the
harness can call into `RNS` directly to obtain expected outputs and assert
the asm produces the same bytes. These helpers sit between the test and
`RNS.*` so a test like::

    expected_frames = oracle.kiss_decode(stream)
    asm_frames = run_asm_kiss_decode(stream)
    assert asm_frames == expected_frames

is one line.

The oracle is intentionally minimal here. New helpers land alongside the
asm function they validate; over-fitting the API in advance buys nothing.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from typing import Any

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD


def _require(module_name: str) -> Any:
    """Import a module from the upstream Python reference, raising a clear
    error if RNS is not installed.
    """
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise RuntimeError(
            f"oracle requires upstream Reticulum: cannot import {module_name}; "
            "install with `pip install rns`"
        ) from exc


# -------------------------------------------------------------------------
# KISS — pure-Python reference for both encode and decode. Used by the kiss
# function tests in milestone 1.
# -------------------------------------------------------------------------


def kiss_encode(payload: bytes) -> bytes:
    """Frame `payload` with KISS escaping. Output starts and ends with FEND."""
    out = bytearray([KISS_FEND, 0x00])  # type 0 = data frame
    for b in payload:
        if b == KISS_FEND:
            out.extend([KISS_FESC, KISS_TFEND])
        elif b == KISS_FESC:
            out.extend([KISS_FESC, KISS_TFESC])
        else:
            out.append(b)
    out.append(KISS_FEND)
    return bytes(out)


def kiss_decode(stream: Iterable[int]) -> list[bytes]:
    """Decode a sequence of bytes (any iterable yielding ints 0..255) into
    frame payloads. Drops the type byte (KISS port/command). Raises ValueError
    on a malformed escape sequence.
    """
    frames: list[bytes] = []
    buf = bytearray()
    in_frame = False
    escaped = False
    saw_type = False

    for b in stream:
        if b == KISS_FEND:
            if in_frame and buf:
                frames.append(bytes(buf))
            buf.clear()
            in_frame = True
            saw_type = False
            escaped = False
            continue
        if not in_frame:
            continue
        if not saw_type:
            saw_type = True  # consume the type/command byte
            continue
        if escaped:
            if b == KISS_TFEND:
                buf.append(KISS_FEND)
            elif b == KISS_TFESC:
                buf.append(KISS_FESC)
            else:
                raise ValueError(f"bad escape: 0xDB 0x{b:02x}")
            escaped = False
            continue
        if b == KISS_FESC:
            escaped = True
            continue
        buf.append(b)
    return frames


# -------------------------------------------------------------------------
# Reticulum packet header — defer to the upstream parser. The asm parser
# must produce the same field values for the same input bytes.
# -------------------------------------------------------------------------


def packet_parse(buf: bytes) -> dict[str, Any]:
    """Parse a Reticulum packet header using the upstream Python reference.

    Returns a dict with the same field names the asm parser populates in
    its struct. We restrict the dict to fields milestone 1 cares about
    (header byte, hops, destination hash, payload offset/length); fuller
    field coverage is added in later milestones.
    """
    rns_packet = _require("RNS.Packet")
    # Upstream's Packet.from_bytes is the canonical entrypoint; if its
    # signature changes we adapt here, not in every test.
    pkt = rns_packet.Packet.__new__(rns_packet.Packet)
    pkt.unpack(buf)
    return {
        "header_byte": buf[0],
        "hops": buf[1],
        "dest_hash": pkt.destination_hash,
        "packet_type": pkt.packet_type,
        "payload": pkt.data,
    }
