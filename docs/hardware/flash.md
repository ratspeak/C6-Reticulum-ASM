# ESP32-C6 Flash Persistence Contract

Milestone 4 persists the local Reticulum identity in one bounded flash region
on the Adafruit ESP32-C6 Feather. This document is the TARGET_C6 hardware
contract for `flash_init`, `flash_read`, `flash_write_page`,
`flash_erase_sector`, `identity_save`, and `identity_load`.

This is not an implementation proof. Register-level or ROM-helper sequencing
for erase/program/read still belongs with the production flash backend and its
verifier artifacts.

## Primary References

- [Adafruit ESP32-C6 Feather overview](https://learn.adafruit.com/adafruit-esp32-c6-feather/overview):
  confirms the project board ships with 4 MB flash.
- [Espressif ESP32-C6 Series Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c6_datasheet_en.pdf):
  lists `ESP32-C6FH4` as 4 MB Quad SPI in-package flash and notes the
  in-package flash does not support flash auto-suspend by default.
- [ESP-IDF ESP32-C6 SPI Flash API](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/index.html):
  documents the main SPI flash model, partition-bounds guidance, 4 KiB sector
  erase alignment, and the NOR rule that writes require previously-erased
  bytes because bits only program from `1` to `0`.
- [ESP-IDF ESP32-C6 SPI1 flash concurrency constraints](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/spi_flash_concurrency.html):
  documents that ESP32-C6 cache must be disabled during flash
  read/write/erase on SPI1, and that code/data used during that window must be
  in internal RAM.

## Confirmed Facts

- The supported hardware target is the Adafruit ESP32-C6 Feather, currently
  built and flashed as `TARGET=c6`.
- The board flash capacity used by this project is 4 MiB
  (`0x0040_0000` bytes). The current `make image TARGET=c6` path also passes
  `--flash-size 4MB`.
- The firmware image is flashed at chip offset `0x0000_0000` by
  `make flash TARGET=c6`.
- The C6 linker script currently places the whole production image in HP SRAM
  at boot. No production code is intended to execute from flash while the
  milestone-4 flash routines run.
- Sector erase granularity for the contract is 4 KiB. Erase offsets and lengths
  must be multiples of `0x1000`.
- SPI NOR flash writes may only change erased `1` bits to programmed `0` bits.
  The software contract must reject any attempted byte update where
  `(old_byte & new_byte) != new_byte`.

## Contract Assumptions

- The milestone-4 write quantum is one 256-byte page. This matches the common
  SPI NOR page-program size and ESP-IDF's page-program abstraction, but the
  production TARGET_C6 backend must still confirm the in-package flash driver's
  effective page size before marking `flash_write_page` verified.
- The exact backend sequence is not yet proven. Production asm may use ROM SPI
  flash helpers or direct MSPI/SPI1 registers, but it must satisfy the same
  external contract and pass hardware reset-retention tests.
- Flash encryption and secure boot are out of scope. If either is enabled
  later, this document needs a new ADR or superseding hardware contract because
  raw flash reads and encrypted cache reads have different semantics.

## Reserved Region

Milestone 4 reserves the final 4 KiB sector of the 4 MiB flash address space:

| Name | Value |
|------|-------|
| Flash chip size | `0x0040_0000` bytes |
| Identity sector absolute offset | `0x003F_F000` |
| Identity region size | `0x0000_1000` bytes |
| Sector size | `0x0000_1000` bytes |
| Page size | `0x0000_0100` bytes |
| Identity record offset within region | `0x0000_0000` |

The choice is intentionally boring: it keeps the identity record outside the
current image-at-zero boot path, is naturally sector-aligned, and leaves the
record at a stable absolute address until a real partition table exists.

No production API accepts absolute flash addresses. Public flash functions take
only offsets inside the reserved identity region. The TARGET_C6 backend adds
`0x003F_F000` internally after proving `offset + len <= 0x1000` without
unsigned wraparound.

## Layout

The only valid record starts at region offset `0`.

| Range | Meaning |
|-------|---------|
| `0x000..0x0FF` | 256-byte milestone-4 identity record page |
| `0x100..0xFFF` | Erased padding, reserved for future slots or metadata |

The identity record format itself is defined in
[milestone-4.md](../milestones/milestone-4.md#identity-record). Padding outside
the first page must remain `0xff` after `identity_save`.

## TARGET_C6 Backend Rules

- `flash_init` must validate that the reserved absolute offset and size are
  sector-aligned, and must reject any detected chip size smaller than 4 MiB.
- `flash_read(offset, out, len)` may read any byte range inside the 4 KiB
  region. Zero-length reads are no-ops.
- `flash_write_page(offset, src, len)` must reject:
  - zero-length writes,
  - writes outside the 4 KiB identity region,
  - writes crossing a 256-byte page boundary,
  - any write that would program a `0` bit back to `1`.
- `flash_erase_sector(offset)` only accepts `offset == 0` for milestone 4 and
  sets the whole identity sector to `0xff`.
- Validation happens before modification. On any rejected write or erase,
  storage must remain unchanged.
- No operation may call chip erase, write outside `0x003F_F000..0x003F_FFFF`,
  or expose a caller-controlled absolute address.
- Erase/write/read code and all data it touches must be in internal RAM while
  the flash bus is active. The current linker script already satisfies this for
  the whole image; if future code moves to XIP, the flash backend must be
  revisited.
- No logging is permitted while erase/program is in progress. Log only status
  events after flash operations complete, and never log private key material.

## Identity Save/Load Flow

`identity_save` must:

1. Recompute and validate `identity.hash`.
2. Build the 256-byte record in static RAM scratch.
3. Erase the identity sector.
4. Program the 256-byte record page.
5. Read the page back and byte-compare it to scratch.
6. Leave `0x100..0xFFF` erased.

`identity_load` must:

1. Read the first 256 bytes.
2. Treat all-`0xff` as missing identity.
3. Reject bad magic, version, flags, header length, identity length, checksum,
   or recomputed identity hash.
4. Copy only the 160-byte `identity_t` payload to the caller.

## Flashing Safety

Normal `make flash TARGET=c6` writes the ESP image at offset `0x0`. It must not
intentionally erase or overwrite the top identity sector. The following actions
destroy the persisted identity and are test-fixture setup steps only:

- `esptool erase_flash`
- `write_flash` over a range that overlaps `0x003F_F000..0x003F_FFFF`
- any future image whose generated flash span reaches the identity sector

If production images grow toward the reserved sector, the build must fail before
generating a flashable image. Moving the identity sector or introducing an
ESP-IDF-style partition table is an ADR-level decision.

## Reset-Retention Validation Plan

The TARGET_C6 hardware test must prove persistence without reflashing between
the save and load phases.

1. Build and flash `TARGET=c6` once.
2. Start the board and drain to `boot.ready`.
3. Trigger the milestone-4 load-or-create command path.
4. If the sector is erased, expect `identity.created` followed by
   `identity.saved`; record the public identity hash emitted by the test path.
5. Reset the board through `HwTarget` with `auto_flash=False`.
6. Trigger the same path again.
7. Expect `identity.loaded` and the same public identity hash.
8. Build and send an announce using the loaded identity; validate the announce
   with the Python Reticulum oracle.
9. Negative setup tests may erase the identity sector and corrupt one record
   field at a time, but each must restore the sector before exiting.

The test must not pass by accidentally preserving host-side state. The observed
hash has to come from the C6 after a reset and without `make flash` running in
between.

Until the production dispatcher exposes the flash/identity events, the hardware
test in `tests/hardware/test_flash_persistence.py` is a skipped contract anchor.
