"""Tests for tests/harness/oracle.py."""

from __future__ import annotations

import pytest

from harness import oracle


def test_kiss_encode_round_trip() -> None:
    payload = b"hello"
    framed = oracle.kiss_encode(payload)
    assert framed[0] == 0xC0 and framed[-1] == 0xC0
    decoded = oracle.kiss_decode(framed)
    assert decoded == [payload]


def test_kiss_encode_escapes_fend() -> None:
    payload = bytes([0xC0, 0xDB, 0x42])
    framed = oracle.kiss_encode(payload)
    # Body must contain the escape sequences and not the raw bytes.
    body = framed[2:-1]
    assert 0xC0 not in body
    # 0xDB only appears as the start of an escape pair.
    i = 0
    while i < len(body):
        if body[i] == 0xDB:
            assert body[i + 1] in (0xDC, 0xDD)
            i += 2
        else:
            i += 1
    decoded = oracle.kiss_decode(framed)
    assert decoded == [payload]


def test_kiss_decode_multi_frame_stream() -> None:
    a = oracle.kiss_encode(b"alpha")
    b = oracle.kiss_encode(b"beta")
    decoded = oracle.kiss_decode(a + b)
    assert decoded == [b"alpha", b"beta"]


def test_kiss_decode_drops_garbage_outside_frames() -> None:
    framed = oracle.kiss_encode(b"x")
    decoded = oracle.kiss_decode(b"\x99\x88" + framed + b"\x00")
    assert decoded == [b"x"]


def test_kiss_decode_bad_escape_raises() -> None:
    bad = bytes([0xC0, 0x00, 0xDB, 0x99, 0xC0])
    with pytest.raises(ValueError):
        oracle.kiss_decode(bad)
