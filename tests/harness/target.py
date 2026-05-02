"""Target abstraction for the test harness (ADR-0005).

A `Target` is "something I can flash a binary onto, send bytes to, and read
bytes from." Three concrete targets:

* `EmuTarget` — drives qemu-system-riscv32 with a flashed `.bin`. Default for
  agent work; fastest. Requires `qemu-system-riscv32` on PATH.
* `HwTarget` — drives a physical Adafruit ESP32-C6 Feather over USB-serial.
  Flashes via `esptool.py`. Required for hardware-contract validation.
* `NullTarget` — in-memory loopback for unit-testing the harness itself
  (target abstraction, log parser plumbing, dispatcher contract). Always
  available; runs nothing.

The Reticulum-protocol `OracleTarget` (running a Python reference for
differential testing) lives in `oracle.py` because it is not byte-stream
shaped — it answers "given this input, what does the reference produce?"
rather than "here's a process you can talk to."

Availability is a target-level concern. `Target.is_available()` returns False
when the required tool/device is missing. The dispatcher uses this to skip
unavailable targets without failing.
"""

from __future__ import annotations

import abc
import dataclasses
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Iterable
from pathlib import Path

# Module is configured but not used in the current skeleton. Imports are
# kept so subclasses can use them once the implementations land.
__all__ = [
    "Target",
    "TargetUnavailable",
    "TargetConfig",
    "EmuTarget",
    "HwTarget",
    "NullTarget",
    "all_targets",
]


class TargetUnavailable(RuntimeError):
    """Raised when a target's underlying tool/device is not present."""


@dataclasses.dataclass
class TargetConfig:
    """Configuration the dispatcher hands to each target.

    Fields are deliberately broad; concrete targets pick what they need.
    """

    binary: Path | None = None
    serial_port: str | None = None
    qemu_binary: str = "qemu-system-riscv32"
    qemu_machine: str = "virt"  # placeholder until we have a C6-aware model
    qemu_extra_args: tuple[str, ...] = ()
    flash_baud: int = 460800
    log_baud: int = 115200


class Target(abc.ABC):
    """Abstract target. Concrete subclasses wire start/stop/IO to a real
    process or device.
    """

    name: str

    def __init__(self, config: TargetConfig | None = None) -> None:
        self.config = config or TargetConfig()

    # --- lifecycle ---

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True iff this target can run right now."""

    @abc.abstractmethod
    def start(self) -> None:
        """Bring the target up. Must call `is_available()` first; raises
        `TargetUnavailable` if not."""

    @abc.abstractmethod
    def stop(self) -> None:
        """Tear down. Must be safe to call when not started."""

    # --- I/O ---

    @abc.abstractmethod
    def write(self, data: bytes) -> None:
        """Send bytes toward the target's RX (the host TX pin)."""

    @abc.abstractmethod
    def read(self, max_bytes: int, timeout: float) -> bytes:
        """Read up to `max_bytes` from the target's TX. Returns whatever has
        accumulated within `timeout` seconds, possibly empty."""

    # --- convenience ---

    def read_lines(self, timeout: float) -> list[str]:
        """Drain the target for `timeout` seconds, returning decoded lines.
        Default implementation: read in chunks and split. Subclasses that
        track partial lines may override.
        """
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = self.read(4096, min(remaining, 0.05))
            if chunk:
                buf.extend(chunk)
            elif buf:
                # No new bytes and we have something queued — return now.
                break
        text = buf.decode("utf-8", errors="replace")
        # Keep CR/LF intact; the caller's parser strips them.
        return [line for line in text.splitlines() if line]

    def __enter__(self) -> "Target":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


# -------------------------------------------------------------------------
# NullTarget — in-memory loopback. Useful for harness self-tests and for
# placeholder runs when no hardware is available. Bytes written are stored;
# reads return scripted bytes the test set up via `inject()`.
# -------------------------------------------------------------------------


class NullTarget(Target):
    name = "null"

    def __init__(self, config: TargetConfig | None = None) -> None:
        super().__init__(config)
        self._tx_log = bytearray()
        self._rx_queue = bytearray()
        self._lock = threading.Lock()
        self._started = False

    def is_available(self) -> bool:
        return True

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        self._started = False

    def write(self, data: bytes) -> None:
        if not self._started:
            raise RuntimeError("NullTarget.write before start")
        with self._lock:
            self._tx_log.extend(data)

    def read(self, max_bytes: int, timeout: float) -> bytes:
        if not self._started:
            raise RuntimeError("NullTarget.read before start")
        # We are an in-memory target; no real waiting. Honor max_bytes only.
        with self._lock:
            chunk = bytes(self._rx_queue[:max_bytes])
            del self._rx_queue[:max_bytes]
        return chunk

    # --- test helpers ---

    def inject(self, data: bytes) -> None:
        """Make `data` available to subsequent `read` calls."""
        with self._lock:
            self._rx_queue.extend(data)

    def written(self) -> bytes:
        with self._lock:
            return bytes(self._tx_log)


# -------------------------------------------------------------------------
# EmuTarget — qemu-system-riscv32 wrapper. Skeleton: detection works; full
# wiring (machine model, semihosting, log routing) lands once we have a
# binary to run. Until then, `start()` raises `TargetUnavailable` with a
# clear message.
# -------------------------------------------------------------------------


class EmuTarget(Target):
    """qemu-system-riscv32 wrapper. Launch model:

        qemu-system-riscv32 -machine virt -cpu rv32 -bios none
            -kernel <elf> -display none -serial stdio
            -monitor none -no-reboot

    UART0 (NS16550A in qemu's virt model) is multiplexed with qemu's
    stdio, so the host can write bytes to qemu's UART RX by writing
    proc.stdin, and read bytes from qemu's UART TX by reading proc.stdout.

    A daemon thread drains stdout into an internal buffer; `read()`
    serves from that buffer with a timeout. This avoids blocking the
    main thread on a slow guest while still presenting a synchronous
    API.
    """

    name = "emu"

    def __init__(self, config: TargetConfig | None = None) -> None:
        super().__init__(config)
        self._proc: subprocess.Popen | None = None
        self._rx_buf: bytearray = bytearray()
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None

    def is_available(self) -> bool:
        return shutil.which(self.config.qemu_binary) is not None and \
               self.config.binary is not None and self.config.binary.exists()

    def start(self) -> None:
        if shutil.which(self.config.qemu_binary) is None:
            raise TargetUnavailable(
                f"{self.config.qemu_binary} not on PATH; "
                "install qemu (brew install qemu) to use EmuTarget"
            )
        if self.config.binary is None:
            raise TargetUnavailable(
                "EmuTarget needs config.binary set to a built .elf"
            )
        if not self.config.binary.exists():
            raise TargetUnavailable(
                f"EmuTarget binary {self.config.binary} does not exist"
            )

        cmd = [
            self.config.qemu_binary,
            "-machine", self.config.qemu_machine,
            "-cpu", "rv32",
            "-bios", "none",
            "-kernel", str(self.config.binary),
            "-display", "none",
            "-serial", "stdio",
            "-monitor", "none",
            "-no-reboot",
            *self.config.qemu_extra_args,
        ]
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        fd = self._proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with self._lock:
                self._rx_buf.extend(chunk)

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2.0)
        finally:
            if self._proc.stdin:
                self._proc.stdin.close()
            if self._proc.stdout:
                self._proc.stdout.close()
            self._proc = None
            self._reader = None

    def write(self, data: bytes) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("EmuTarget.write before start")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def read(self, max_bytes: int, timeout: float) -> bytes:
        if self._proc is None:
            raise RuntimeError("EmuTarget.read before start")
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._rx_buf:
                    chunk = bytes(self._rx_buf[:max_bytes])
                    del self._rx_buf[:max_bytes]
                    return chunk
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b""
            time.sleep(min(remaining, 0.01))


# -------------------------------------------------------------------------
# HwTarget — physical Feather over USB-serial. Skeleton with detection;
# flashing and serial I/O land when the build chain produces a `.bin`.
# -------------------------------------------------------------------------


class HwTarget(Target):
    name = "hw"

    def __init__(self, config: TargetConfig | None = None) -> None:
        super().__init__(config)
        self._serial = None  # type: ignore[assignment]

    def is_available(self) -> bool:
        if shutil.which("esptool.py") is None and shutil.which("esptool") is None:
            return False
        if self.config.serial_port is None:
            return False
        return Path(self.config.serial_port).exists()

    def start(self) -> None:
        if not self.is_available():
            raise TargetUnavailable(
                "HwTarget unavailable: esptool and a serial port "
                "(config.serial_port) are required"
            )
        raise TargetUnavailable(
            "HwTarget.start: flash + serial wiring is not implemented yet "
            "(blocked on first flashable .bin)"
        )

    def stop(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None

    def write(self, data: bytes) -> None:
        raise TargetUnavailable("HwTarget I/O not implemented yet")

    def read(self, max_bytes: int, timeout: float) -> bytes:
        raise TargetUnavailable("HwTarget I/O not implemented yet")


def all_targets(config: TargetConfig | None = None) -> Iterable[Target]:
    """Iterate every defined target in priority order. The dispatcher filters
    by `is_available()`."""
    yield NullTarget(config)
    yield EmuTarget(config)
    yield HwTarget(config)
