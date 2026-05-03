/* Static SX1262 command scratch buffers (ADR-0002).
 *
 * Command helpers serialize opcode/argument/dummy bytes into the TX scratch
 * buffer and read full-duplex response bytes into the RX scratch buffer.
 */

        .include "lora.S"

        .section .bss.sx1262_command_model, "aw", @nobits
        .balign 4
        .global sx1262_command_tx_buf
        .type   sx1262_command_tx_buf, @object
sx1262_command_tx_buf:
        .skip   SPI_MAX_TRANSFER
        .size   sx1262_command_tx_buf, SPI_MAX_TRANSFER

        .global sx1262_command_rx_buf
        .type   sx1262_command_rx_buf, @object
sx1262_command_rx_buf:
        .skip   SPI_MAX_TRANSFER
        .size   sx1262_command_rx_buf, SPI_MAX_TRANSFER
