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

        .global sx1262_model_initialized
        .type   sx1262_model_initialized, @object
sx1262_model_initialized:
        .skip   4
        .size   sx1262_model_initialized, 4

        .global sx1262_model_init_error
        .type   sx1262_model_init_error, @object
sx1262_model_init_error:
        .skip   4
        .size   sx1262_model_init_error, 4

        .global sx1262_model_status_byte
        .type   sx1262_model_status_byte, @object
sx1262_model_status_byte:
        .skip   4
        .size   sx1262_model_status_byte, 4

        .global sx1262_frame_tx_buf
        .type   sx1262_frame_tx_buf, @object
sx1262_frame_tx_buf:
        .skip   SPI_MAX_TRANSFER
        .size   sx1262_frame_tx_buf, SPI_MAX_TRANSFER

        .global sx1262_tx_packet_params_buf
        .type   sx1262_tx_packet_params_buf, @object
sx1262_tx_packet_params_buf:
        .skip   8
        .size   sx1262_tx_packet_params_buf, 8

        .global sx1262_irq_read_buf
        .type   sx1262_irq_read_buf, @object
sx1262_irq_read_buf:
        .skip   4
        .size   sx1262_irq_read_buf, 4

        .global sx1262_model_tx_len
        .type   sx1262_model_tx_len, @object
sx1262_model_tx_len:
        .skip   4
        .size   sx1262_model_tx_len, 4

        .global sx1262_model_last_irq
        .type   sx1262_model_last_irq, @object
sx1262_model_last_irq:
        .skip   4
        .size   sx1262_model_last_irq, 4

        .global sx1262_frame_rx_buf
        .type   sx1262_frame_rx_buf, @object
sx1262_frame_rx_buf:
        .skip   SPI_MAX_TRANSFER
        .size   sx1262_frame_rx_buf, SPI_MAX_TRANSFER

        .global sx1262_rx_status_buf
        .type   sx1262_rx_status_buf, @object
sx1262_rx_status_buf:
        .skip   4
        .size   sx1262_rx_status_buf, 4

        .global sx1262_read_buffer_req_buf
        .type   sx1262_read_buffer_req_buf, @object
sx1262_read_buffer_req_buf:
        .skip   4
        .size   sx1262_read_buffer_req_buf, 4

        .global sx1262_model_rx_len
        .type   sx1262_model_rx_len, @object
sx1262_model_rx_len:
        .skip   4
        .size   sx1262_model_rx_len, 4
