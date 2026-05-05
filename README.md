# RISC-V-C6
#### Warning: Experimental - this is the result of boredom, spare LLM compute, and wanting to test its capability. No guarantees.

Pure RV32IMAC assembly firmware for experimenting with Reticulum on the
Adafruit ESP32-C6 Feather.

This is a research and bring-up project. It is not a production Reticulum node,
not a drop-in RNode replacement, and not a general ESP32-C6 SDK project.

## Current State

The repo currently has assembly implementations for:

- boot, clock, UART, logging, KISS framing, and packet helpers
- SHA-256, SHA-512, HMAC, HKDF, AES-256-CBC, X25519, Ed25519, and RNG/DRBG
- identity creation, destination hashes, announce build/send, announce parse/validate
- flash-backed identity persistence
- basic transport path handling
- link/session helpers
- resource/channel helpers
- SX1262 GPIO/SPI/LoRa interface foundation
- early LXMF payload/message-id/delivery-announce helpers

The current active work is the LXMF foundation. See
[FUNCTIONS.md](FUNCTIONS.md) for the live function registry.

## Hardware

Primary target:

- Adafruit ESP32-C6 Feather
- Wio-SX1262 V1.0 header carrier for LoRa testing

The LoRa wiring is still bench-specific and experimental.

## Verification

The project uses layered verification, not a blanket proof of the whole
firmware. Depending on the function, coverage may include Python/KAT tests,
qemu tests, Cryptol/SAW specs, Binsec constant-time checks, angr/pypcode bounded
checks, and TLA+ state models.

The future `macaw-riscv`/SAW ELF-lifting path is documented, but not in use yet.

## Basic Commands

```sh
make ci
./verify --all
make build TARGET=qemu-virt
make build TARGET=c6
```

Hardware tests require a connected board:

```sh
python3 -m pytest --hardware --hardware-port /dev/cu.usbmodem4101 tests/hardware/ -q
```

## Repository Map

- [FUNCTIONS.md](FUNCTIONS.md) - function registry and verification status
- [src/](src/) - assembly sources
- [tests/](tests/) - Python test harness
- [proofs/](proofs/) - verification artifacts
- [toolchain/](toolchain/) - linker scripts and toolchain notes
