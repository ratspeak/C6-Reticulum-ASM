"""Tests for src/boot/_init_data.S — placeholder while the function is a stub.

When the body is implemented, this module asserts:

* `.data` content is identical to the linker's load image after _init_data
  returns (round-trip: read SRAM at __data_start..__data_end, compare).
* On qemu-virt the function is a no-op (kernel loaded directly into DRAM);
  no observable side effect, but no fault either.
"""

import pytest


@pytest.mark.skip(reason="_init_data is a stub (unimp); test lands with the implementation")
def test_copies_data_section() -> None:
    raise NotImplementedError
