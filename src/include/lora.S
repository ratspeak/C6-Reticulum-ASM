/* SX1262/LoRa interface constants for milestone 8. */

        .include "spi.S"

        .equ LORA_OK,                       0
        .equ LORA_ERR_GPIO,                -1
        .equ LORA_ERR_BUSY_TIMEOUT,        -2
        .equ LORA_ERR_INVAL,               -3
        .equ LORA_ERR_SPI_TIMEOUT,         -4
        .equ LORA_ERR_SPI,                 -5

        .equ SX1262_RESET_LOW_US,           100
        .equ SX1262_RESET_SETTLE_US,        100
        .equ SX1262_BUSY_POLL_DELAY_US,     10
        .equ SX1262_BUSY_TIMEOUT_DEFAULT,   10000
        .equ SX1262_COMMAND_TIMEOUT_DEFAULT, 10000
