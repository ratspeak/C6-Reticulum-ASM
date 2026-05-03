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

        .equ FLASH_OK,                      0
        .equ FLASH_ERR_INVAL,               -1
