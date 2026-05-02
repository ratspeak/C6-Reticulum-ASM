"""Tests for tests/harness/log_parser.py."""

from __future__ import annotations

import pytest

from harness import log_parser as lp


def test_parse_canonical_line() -> None:
    line = "00012345\tkiss\trx_frame\tlen=64\tdest=a1b2c3d4\r\n"
    ev = lp.parse_line(line)
    assert ev is not None
    assert ev.ts_raw == "00012345"
    assert ev.ts_ms == 0x12345
    assert ev.module == "kiss"
    assert ev.event == "rx_frame"
    assert ev.fields == {"len": "64", "dest": "a1b2c3d4"}


def test_no_fields_ok() -> None:
    line = "00000001\tboot\tready\r\n"
    ev = lp.parse_line(line)
    assert ev is not None
    assert ev.module == "boot"
    assert ev.event == "ready"
    assert ev.fields == {}


def test_garbage_line_returns_none() -> None:
    assert lp.parse_line("hello world") is None
    assert lp.parse_line("") is None
    assert lp.parse_line("\r\n") is None
    # malformed: ts not hex
    assert lp.parse_line("xx\tkiss\tevent\r\n") is None


def test_value_with_internal_whitespace_rejected() -> None:
    # Per ADR-0004 values must not contain whitespace.
    line = "00000001\tkiss\tev\tx=a b\r\n"
    assert lp.parse_line(line) is None


def test_unix_line_endings_ok() -> None:
    ev = lp.parse_line("00000001\tboot\tready\n")
    assert ev is not None and ev.event == "ready"


def test_parse_lines_drops_non_conforming() -> None:
    text = (
        "boot ROM stage 0\r\n"
        "00000001\tboot\tready\r\n"
        "garbage\r\n"
        "00000002\tuart\trx\tbyte=ff\r\n"
    )
    events = lp.parse_lines(text.splitlines())
    assert [e.event for e in events] == ["ready", "rx"]


def test_find_event_by_field() -> None:
    events = lp.parse_lines(
        [
            "00000001\tkiss\trx_frame\tdest=aaaa\r\n",
            "00000002\tkiss\trx_frame\tdest=bbbb\r\n",
        ]
    )
    found = lp.find_event(events, module="kiss", event="rx_frame", dest="bbbb")
    assert found is not None and found.fields["dest"] == "bbbb"


def test_assert_event_raises_when_missing() -> None:
    events = lp.parse_lines(["00000001\tboot\tready\r\n"])
    with pytest.raises(AssertionError):
        lp.assert_event(events, module="kiss", event="rx_frame")


def test_find_all_returns_every_match() -> None:
    events = lp.parse_lines(
        [
            "00000001\tkiss\trx_frame\tlen=10\r\n",
            "00000002\tkiss\trx_frame\tlen=20\r\n",
            "00000003\tkiss\ttx_frame\tlen=30\r\n",
        ]
    )
    matches = lp.find_all(events, module="kiss", event="rx_frame")
    assert [m.fields["len"] for m in matches] == ["10", "20"]


def test_event_indexing() -> None:
    ev = lp.parse_line("00000001\tk\te\ta=1\tb=2\r\n")
    assert ev is not None
    assert ev["a"] == "1"
    assert ev.get("c") is None
    assert ev.get("c", "z") == "z"
