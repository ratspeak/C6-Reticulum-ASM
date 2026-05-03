/* Milestone-4 flash layout constants.
 *
 * The first backend is the qemu-virt model: one reserved 4 KiB identity
 * sector with 256-byte programmable pages. Offsets accepted by the flash
 * APIs are relative to this reserved region, never raw chip addresses.
 */

        .equ FLASH_SECTOR_SIZE,             4096
        .equ FLASH_PAGE_SIZE,               256
        .equ FLASH_IDENTITY_REGION_SIZE,    4096
        .equ FLASH_IDENTITY_RECORD_OFFSET,  0

        .equ FLASH_C6_CHIP_SIZE,            0x00400000
        .equ FLASH_C6_IDENTITY_ABS_OFFSET,  0x003ff000

        .equ ESP_ROM_SPIFLASH_ERASE_SECTOR, 0x40000144
        .equ ESP_ROM_SPIFLASH_WRITE,        0x4000014c
        .equ ESP_ROM_SPIFLASH_READ,         0x40000150

        .equ FLASH_OK,                      0
        .equ FLASH_ERR_INVAL,               -1
