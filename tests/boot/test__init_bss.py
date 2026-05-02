"""Tests for src/boot/_init_bss.S — placeholder while the function is a stub.

When the body is implemented, this module exercises:

* zeroing of the .bss region between __bss_start and __bss_end,
* unaligned start/end addresses (we expect them to be 4-byte aligned by the
  linker; assert that),
* round-trip with a known non-zero pre-state (only meaningful with a custom
  test harness that pre-populates .bss before calling).

Currently `_init_bss` is `unimp`; the placeholder test below documents the
contract without exercising it.
"""

import pytest


@pytest.mark.skip(reason="_init_bss is a stub (unimp); test lands with the implementation")
def test_zeroes_bss_region() -> None:
    raise NotImplementedError
