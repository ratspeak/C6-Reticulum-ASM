"""Tests for tests/harness/target.py.

The Emu and Hw target implementations are skeleton-only at this point in
milestone 1 (no .bin to run). These tests cover the contract that does
exist: NullTarget round-trip, availability detection, and lifecycle.
"""

from __future__ import annotations

import pytest

from harness import target


def test_null_target_round_trip() -> None:
    t = target.NullTarget()
    assert t.is_available()
    with t:
        t.write(b"hello")
        t.inject(b"world")
        assert t.read(5, timeout=0.0) == b"world"
        assert t.written() == b"hello"


def test_null_target_partial_read() -> None:
    t = target.NullTarget()
    with t:
        t.inject(b"abcdef")
        assert t.read(3, timeout=0.0) == b"abc"
        assert t.read(10, timeout=0.0) == b"def"


def test_null_target_read_lines() -> None:
    t = target.NullTarget()
    with t:
        t.inject(b"line one\r\nline two\r\n")
        lines = t.read_lines(timeout=0.05)
    assert lines == ["line one", "line two"]


def test_null_target_use_before_start_raises() -> None:
    t = target.NullTarget()
    with pytest.raises(RuntimeError):
        t.write(b"x")
    with pytest.raises(RuntimeError):
        t.read(1, 0.0)


def test_emu_target_requires_a_binary() -> None:
    """Without a `binary` in the config, EmuTarget can't run anything;
    is_available is False even when qemu is installed."""
    t = target.EmuTarget(target.TargetConfig(binary=None))
    assert not t.is_available()
    with pytest.raises(target.TargetUnavailable):
        t.start()


def test_hw_target_unavailable_without_port() -> None:
    cfg = target.TargetConfig(serial_port=None)
    t = target.HwTarget(cfg)
    assert not t.is_available()
    with pytest.raises(target.TargetUnavailable):
        t.start()


def test_all_targets_iterates_three() -> None:
    targets = list(target.all_targets())
    names = [t.name for t in targets]
    assert names == ["null", "emu", "hw"]
