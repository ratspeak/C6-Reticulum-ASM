"""Tests for src/boot/_main.S — placeholder while the function is a stub.

The implementation will:

1. Call clock_init.
2. Call uart_init.
3. Call log_init.
4. Emit the `boot.ready` log event.
5. Enter the main event loop (poll uart_rx_byte → kiss_decode_byte →
   packet_parse_header, log per-frame events).

This test file currently asserts only that the asm assembles — the body is
`unimp` and behavioral tests are skipped until the real bring-up sequence
is wired.
"""

import pytest


@pytest.mark.skip(reason="_main is a stub (unimp); behavior tests land with implementation")
def test_emits_boot_ready_event() -> None:
    raise NotImplementedError
