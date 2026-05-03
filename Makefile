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
#   make flash                        TODO once esptool path is wired
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
SRC_DIRS    := src/boot src/clock src/uart src/log src/kiss src/packet src/state src/crypto/sha256 src/crypto/hmac src/crypto/hkdf src/crypto/aes src/crypto/x25519 src/crypto/rng
SRCS        := $(wildcard $(addsuffix /*.S,$(SRC_DIRS)))
OBJS        := $(patsubst src/%.S,$(BUILD_DIR)/%.o,$(SRCS))
ELF         := $(BUILD_DIR)/firmware.elf
BIN         := $(BUILD_DIR)/firmware.bin

ASFLAGS     := $(ARCH_FLAGS) $(ASDEFS) -I src/include
LDFLAGS     := -nostdlib -static --no-warn-rwx-segments

.PHONY: help test tools-test registry spec verify verify-all ci build emu flash clean

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
	@echo "  flash          TODO: esptool path not wired yet"
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

flash:
	@echo "TODO: esptool flash path not wired yet (needs C6 image header per docs/hardware/image-header.md)"
	@false

clean:
	rm -rf build/
