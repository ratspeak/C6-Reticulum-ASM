# Top-level Makefile.
#
# Targets (host-side):
#   make test         run the host-side test suite (pytest)
#   make registry     cross-check FUNCTIONS.md against src/
#   make spec FILE=…  validate one spec block
#   make verify FN=…  dispatch one function's tests + verifier
#   make verify-all   dispatch every registered function
#   make ci           equivalent to: registry + test
#
# Targets (target-side, requires riscv64-elf-binutils + qemu, see ADR-0008):
#   make build [TARGET=qemu-virt|c6]  assemble + link → build/firmware.elf
#   make emu                          run firmware.elf in qemu-system-riscv32
#   make image                        TARGET=c6 only — wraps ELF in ESP image format
#   make flash                        TARGET=c6 only — esptool write_flash 0x0
#   make monitor                      open serial monitor on the C6 USB-Serial/JTAG
#   make clean                        rm -rf build/

PYTHON      := python3
# Use := (not ?=) so make's built-in AS=as default does not override us.
# Override on the command line: `make build AS=path/to/as`.
AS          := riscv64-elf-as
LD          := riscv64-elf-ld
OBJCOPY     := riscv64-elf-objcopy
OBJDUMP     := riscv64-elf-objdump
QEMU        := qemu-system-riscv32

# Default to the qemu-virt target. The C6 target lands once real-hardware
# bring-up starts (and toolchain/c6.ld exists).
TARGET      ?= qemu-virt
ARCH_FLAGS  := -march=rv32imac -mabi=ilp32

ifeq ($(TARGET),qemu-virt)
    ASDEFS    := --defsym TARGET_QEMU_VIRT=1
    LDSCRIPT  := toolchain/qemu-virt.ld
else ifeq ($(TARGET),c6)
    ASDEFS    := --defsym TARGET_C6=1
    LDSCRIPT  := toolchain/c6.ld
else
    $(error TARGET must be qemu-virt or c6, got '$(TARGET)')
endif

BUILD_DIR   := build/$(TARGET)
SRC_DIRS    := src/boot src/clock src/uart src/log src/kiss src/packet src/state src/crypto/sha256 src/crypto/sha512 src/crypto/hmac src/crypto/hkdf src/crypto/aes src/crypto/x25519 src/crypto/rng src/crypto/ed25519 src/identity src/destination src/announce src/transport src/link src/flash
SRCS        := $(wildcard $(addsuffix /*.S,$(SRC_DIRS)))
OBJS        := $(patsubst src/%.S,$(BUILD_DIR)/%.o,$(SRCS))
ELF         := $(BUILD_DIR)/firmware.elf
BIN         := $(BUILD_DIR)/firmware.bin

ASFLAGS     := $(ARCH_FLAGS) $(ASDEFS) -I src/include
LDFLAGS     := -nostdlib -static --no-warn-rwx-segments

.PHONY: help test tools-test registry spec verify verify-all ci build emu image flash monitor clean

# C6 hardware bring-up. Override on the command line if your board enumerates
# at a different /dev/cu.* path or you want a faster flashing baud.
ESPTOOL     ?= esptool.py
ESP_PORT    ?= /dev/cu.usbmodem4101
ESP_BAUD    ?= 460800
ESP_CHIP    ?= esp32c6
IMAGE_BIN   := build/c6/firmware.image.bin

help:
	@echo "Targets:"
	@echo "  test           run pytest over tests/"
	@echo "  registry       check FUNCTIONS.md <-> src/ agreement"
	@echo "  stack          worst-case stack depth from _reset"
	@echo "  spec FILE=…    validate one spec block (any path)"
	@echo "  verify FN=…    dispatch one function's tests + verifier [JSON=1]"
	@echo "  verify-all     dispatch every registered function"
	@echo "  ci             equivalent to: registry + test"
	@echo "  build [TARGET=qemu-virt|c6]   assemble + link"
	@echo "  emu            run firmware.elf in qemu-system-riscv32"
	@echo "  image          (TARGET=c6) wrap ELF in ESP image header"
	@echo "  flash          (TARGET=c6) esptool write_flash 0x0 \$$IMAGE_BIN"
	@echo "  monitor        open the C6 USB Serial/JTAG (115200, ESP_PORT=$(ESP_PORT))"
	@echo "  clean          remove build/"

test:
	$(PYTHON) -m pytest tests/ -q

tools-test:
	$(PYTHON) -m pytest tests/tools/ -q

registry:
	$(PYTHON) tools/check_registry.py

stack:
	$(PYTHON) tools/check_stack.py

spec:
	@if [ -z "$(FILE)" ]; then echo "usage: make spec FILE=path/to/file.S"; exit 2; fi
	$(PYTHON) tools/parse_spec.py "$(FILE)"

verify:
	@if [ -z "$(FN)" ]; then echo "usage: make verify FN=<function_name> [JSON=1]"; exit 2; fi
	$(PYTHON) verify_cli.py $(if $(JSON),--json) "$(FN)"

verify-all:
	$(PYTHON) verify_cli.py --all $(if $(JSON),--json)

ci: registry stack test

# --- target-side build ----------------------------------------------------

build: $(ELF) $(BIN)

$(BUILD_DIR)/%.o: src/%.S | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -o $@ $<

$(ELF): $(OBJS) $(LDSCRIPT)
	$(LD) $(LDFLAGS) -T $(LDSCRIPT) -o $@ $(OBJS)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	@mkdir -p $@

emu: build
	$(QEMU) -machine virt -cpu rv32 -bios none -kernel $(ELF) \
	        -nographic -no-reboot -d guest_errors

# --- C6 hardware bring-up -------------------------------------------------
# `image` produces an ESP image-format binary that the C6 mask-ROM second-stage
# loader can consume from flash offset 0x0. esptool's elf2image walks PT_LOAD
# program headers, segregates IRAM vs DRAM segments, prepends the image header
# (magic 0xE9, segment count, entry-point address), and appends the SHA-256
# integrity hash. We pass --flash_size 4MB to match the ESP32-C6FH4 part on
# the Adafruit Feather (4 MB embedded NOR flash).
image: build
ifneq ($(TARGET),c6)
	$(error make image only works with TARGET=c6, got '$(TARGET)')
endif
	# DIO + 40 MHz are the conservative defaults that match the Adafruit
	# Feather ESP32-C6's factory flash configuration. QIO at boot returns
	# garbage data on this board — empirically the ROM's segment-data XOR
	# walk reads 0x00 throughout, producing calculated == seed (0xef) and
	# a checksum mismatch. Higher speeds / QIO can be re-enabled once the
	# bootloader-equivalent code reconfigures the SPI controller.
	$(ESPTOOL) --chip $(ESP_CHIP) elf2image --flash-size 4MB \
	           --flash-mode dio --flash-freq 40m \
	           --output $(IMAGE_BIN) $(ELF)

flash: image
	$(ESPTOOL) --chip $(ESP_CHIP) --port $(ESP_PORT) --baud $(ESP_BAUD) \
	           write_flash 0x0 $(IMAGE_BIN)

# Convenience: open a serial monitor. Uses miniterm.py (ships with pyserial,
# which is an esptool dependency, so it is always available alongside esptool).
# Ctrl-] to exit. The C6's USB Serial/JTAG ignores baud rate; 115200 matches
# what the host driver advertises.
monitor:
	$(PYTHON) -m serial.tools.miniterm --raw --eol LF $(ESP_PORT) 115200

clean:
	rm -rf build/
