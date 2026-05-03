# ESP32-C6 SX1262 LoRa Hardware Contract

Milestone 8 adds the first standalone wireless interface: an external Seeed
Wio-SX1262 LoRa module driven directly by the Adafruit ESP32-C6 Feather over
SPI. This document is the TARGET_C6 hardware contract for the milestone-8
GPIO, SPI, SX1262, and LoRa interface functions.

This is not an implementation proof. It is the source of truth for pin
ownership, electrical assumptions, register-document provenance, and the qemu
hardware-model surface that the asm driver and tests must satisfy.

## Primary References

- [ADR-0011](../adr/0011-sx1262-lora-target.md): selects SX1262 as the
  milestone-8 LoRa transceiver.
- [Adafruit ESP32-C6 Feather guide](https://learn.adafruit.com/adafruit-esp32-c6-feather?view=all):
  documents the Feather 3.3 V rail, ESP32-C6 module, SPI header pins
  `SCK=IO21`, `MOSI=IO22`, `MISO=IO23`, UART pins `RX=IO17` and `TX=IO16`,
  I2C pins `SCL=IO18` and `SDA=IO19`, and available digital pins.
- [ESP-IDF ESP32-C6 GPIO documentation](https://docs.espressif.com/projects/esp-idf/en/v5.1.2/esp32c6/api-reference/peripherals/gpio.html):
  documents GPIO matrix routing, strapping pins, USB-JTAG pins, and pins
  reserved for SPI flash.
- [ESP-IDF ESP32-C6 SPI master documentation](https://docs.espressif.com/projects/esp-idf/en/v5.1.2/esp32c6/api-reference/peripherals/spi_master.html):
  documents that SPI0/SPI1 are used for attached flash and SPI2 is the
  general-purpose SPI controller.
- [Seeed Wio-SX1262 module datasheet](https://files.seeedstudio.com/products/SenseCAP/Wio_SX1262/Wio-SX1262_Module_Datasheet.pdf):
  documents the 12-pin module pinout, SPI interface, VCC operating range,
  BUSY, DIO1, NRST, NSS, IPEX antenna default, HF 862-930 MHz range, and
  +22 dBm maximum TX power.
- [Semtech SX1261/2 datasheet](https://www.alldatasheet.net/html-marking/1148171/SEMTECH/SX1262/17045/49/SX1262.html):
  documents SX1262 SPI mode (`CPOL=0`, `CPHA=0`), 16 MHz maximum SCK,
  mandatory BUSY line, reset timing, and command opcodes for register/buffer
  access, IRQ/DIO control, RF setup, packet type, TX params, and modulation
  params.
- Reticulum manual
  `/Users/Games/Desktop/main/docs/reticulum-manual/interfaces/rnode-lora-interface.md`:
  documents the LoRa-facing Reticulum configuration fields: frequency,
  bandwidth, TX power, spreading factor, coding rate, callsign/ID, flow
  control, and airtime limits.
- Upstream Reticulum
  `/Users/Games/reticulum-audit/Reticulum/RNS/Interfaces/RNodeInterface.py`:
  documents the current RNode interface fields and `HW_MTU = 508`.

## Selected Bench Wiring

The first bench configuration uses the Feather header SPI pins plus four GPIOs
that do not overlap UART0, USB-Serial/JTAG, I2C, SPI flash, the Boot/NeoPixel
pin, or the red LED.

| Wio-SX1262 signal | Wio pin | ESP32-C6 GPIO | Feather role | Direction from C6 | Rule |
|-------------------|---------|---------------|--------------|-------------------|------|
| VCC | 8 | 3.3 V rail | 3.3 V | power | Module VCC must stay within the Seeed operating range. |
| GND | 7, 10 | GND | GND | power | Common ground is mandatory. |
| SCK | 4 | GPIO21 | SCK | output | SPI2 SCLK through GPIO matrix or IO_MUX-compatible routing. |
| MOSI | 3 | GPIO22 | MOSI | output | SPI2 MOSI. |
| MISO | 2 | GPIO23 | MISO | input | SPI2 MISO. |
| NSS | 6 | GPIO0 | digital | output | Active-low chip select; idle high before and after every transaction. |
| NRST | 5 | GPIO7 | digital | output | Active-low radio reset; default high after GPIO init. |
| BUSY | 11 | GPIO6 | A2/IO6 | input | Driver must wait for low before each SX1262 command. |
| DIO1 | 12 | GPIO5 | A3/IO5 | input | IRQ input for TX done, RX done, timeout, CRC/error. |
| ANT | 9 | IPEX antenna | RF | RF | Antenna must be attached before TX. |
| RF_SW | 1 | not connected | - | - | First bring-up assumes the module's internal DIO2 RF-switch control path. |

GPIO5 is an ESP32-C6 strapping pin. This contract allows it only for DIO1
because DIO1 is expected to be high-impedance or inactive during reset. The
first hardware test with the SX1262 attached must prove the Feather still boots
normally. If GPIO5 affects boot strapping, the pin map must change before any
driver function using DIO1 can be marked verified.

GPIO12 and GPIO13 are not used because ESP-IDF documents them as USB-JTAG pins
by default, and this project currently relies on the USB-Serial/JTAG path for
diagnostics and hardware tests. GPIO9 is not used because it is shared with the
Boot button and NeoPixel. GPIO15 is not used because it is the red LED pin and
also a strapping pin.

## Electrical Rules

- The Wio-SX1262 module is powered from the Feather 3.3 V rail.
- All signal levels are 3.3 V logic.
- The module must have a suitable antenna attached before any TX test.
- TX power is bounded to the milestone static configuration and must not exceed
  the module/SX1262 documented maximum.
- RF regional compliance is not implemented in milestone 8. Bench tests must
  use a locally legal frequency and power setting selected outside the driver.

## Static Bench Profile

The first driver profile mirrors the Reticulum RNode example shape while
remaining explicit in asm constants:

- Frequency: `867200000` Hz, encoded for SX1262 `SetRfFrequency` as
  `0x36333333`.
- Bandwidth: `125000` Hz (`SX1262_LORA_BW_125_KHZ`).
- Spreading factor: SF8.
- Coding rate: CR 4/5, corresponding to Reticulum `codingrate = 5`.
- TX power: `7` dBm with a 200 us ramp.
- Preamble: 12 symbols.
- Explicit LoRa header, CRC enabled, standard IQ.
- Payload cap: 255 bytes, the SX1262 LoRa packet payload limit for this
  profile. Upper layers must still respect Reticulum's interface MDU.

`sx1262_init` applies this profile and returns the chip to standby. It does not
enter TX or continuous RX by itself.

## SPI Contract

- The production driver uses ESP32-C6 SPI2, not SPI0/SPI1. SPI0/SPI1 are left
  to flash/boot.
- SPI mode is Motorola/Freescale mode 0: `CPOL=0`, `CPHA=0`.
- Bits are transferred most-significant bit first.
- Semtech's SX1261/2 SCK maximum is 16 MHz. The milestone-8 bench default is
  1 MHz until the qemu model and hardware tests prove higher speeds; production
  asm must reject configuration above 16 MHz.
- `spi_transfer(tx, rx, len, timeout)` is the only public byte-exchange
  primitive for SX1262 command traffic in milestone 8.
- Zero-length transfers are no-ops. Non-zero transfers require at least one
  non-null TX or RX buffer.
- Transfers are bounded by a static maximum chosen before implementation.
- The first implementation uses polling, not interrupts or DMA.
- CS ownership belongs to the SX1262 command layer, not the generic SPI byte
  transfer. `sx1262_command_write` and `sx1262_command_read` assert NSS low,
  call `spi_transfer`, and deassert NSS high.

## SX1262 Command Contract

- `sx1262_reset` must hold NRST low for at least 100 us, then release it high
  and wait for BUSY to clear.
- Every command must first observe `BUSY == 0`.
- Commands that write or read register/buffer state use the Semtech opcode
  families for register access, buffer access, IRQ/DIO control, RF setup,
  packet type, TX params, and modulation params.
- `sx1262_init` configures only LoRa packet mode for the static milestone-8
  bench profile.
- DIO1 is the only IRQ line consumed by milestone 8. DIO2/DIO3 remain internal
  module functions unless a later contract revision exposes them.
- The first driver must distinguish at least:
  - command accepted,
  - invalid argument,
  - BUSY timeout,
  - SPI timeout,
  - IRQ error/CRC error,
  - RX overflow,
  - no packet available.

## Reticulum Interface Contract

- The LoRa interface sends and receives raw Reticulum packets. It does not put
  KISS framing on the RF link.
- The USB-Serial/JTAG KISS development path remains available for tests and
  diagnostics while milestone 8 is active.
- The interface payload limit is capped by the smaller of the SX1262 LoRa
  payload limit selected for the bench profile and the upstream Reticulum
  RNode `HW_MTU = 508`.
- `lora_interface_poll` may process at most one received frame per call.
- Valid received frames are handed to the existing packet/transport/link
  dispatch path. Malformed or overflowing frames must not mutate transport,
  link, resource, or identity state.

## QEMU Hardware Model Surface

The qemu model for milestone 8 should expose a deterministic memory-backed
device with these externally visible states:

1. GPIO output latch state for NSS and NRST.
2. GPIO input state for BUSY and DIO1.
3. SPI2 transfer log of bytes written by the driver.
4. SX1262 command parser for the subset used by `sx1262_init`,
   `sx1262_send_frame`, and `sx1262_poll_receive`.
5. FIFO buffer state for one TX frame and one pending RX frame.
6. IRQ status bits for TX done, RX done, timeout, CRC/error, and clear.

The model must make BUSY timeouts, SPI timeouts, RX overflow, and CRC/error
paths injectable from tests.

## Hardware Test Plan

- Boot with the SX1262 physically connected using the selected pin map; verify
  USB-Serial/JTAG diagnostics still work and GPIO5 does not break boot.
- Reset/readback test: drive NRST low/high, wait for BUSY low, then issue a
  harmless status/read command and check for a sane response.
- Init test: configure LoRa packet mode, RF frequency, modulation params,
  packet params, DIO IRQ params, and standby/RX state.
- TX test: write one short Reticulum packet to FIFO, start TX, observe TX done
  or timeout through DIO1/IRQ status.
- RX test: when a second LoRa peer or RF loopback setup is present, receive one
  packet and pass it to the raw packet parser.

## Open Hardware Items

- Vendor the SX1262 datasheet and Wio-SX1262 module pinout, or document
  acquisition steps in `references/README.md` if redistribution is not allowed.
- Confirm whether the specific Wio-SX1262 module on the bench needs external
  RF_SW control or whether internal DIO2 RF-switch control is sufficient.
- Confirm the locally legal bench frequency, bandwidth, spreading factor,
  coding rate, and TX power before enabling any RF TX hardware test.
