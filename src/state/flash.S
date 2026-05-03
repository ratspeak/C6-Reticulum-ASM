/* Static qemu-virt flash model state (ADR-0002).
 *
 * Milestone 4 reserves one identity sector. The qemu model stores that sector
 * in RAM and applies flash write semantics: erased bytes are 0xff, programming
 * may only clear bits, and erase restores the whole sector to 0xff.
 */

        .include "flash.S"

        .section .bss.flash_model, "aw", @nobits

        .global flash_model_region
        .type   flash_model_region, @object
        .balign 4
flash_model_region:
        .zero   FLASH_IDENTITY_REGION_SIZE
        .size   flash_model_region, FLASH_IDENTITY_REGION_SIZE

        .global flash_model_initialized
        .type   flash_model_initialized, @object
        .balign 4
flash_model_initialized:
        .zero   4
        .size   flash_model_initialized, 4
