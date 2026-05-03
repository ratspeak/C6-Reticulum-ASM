/* Static SPI2 model/configuration state (ADR-0002).
 *
 * qemu uses this as a deterministic SPI device model. TARGET_C6 also keeps
 * the initialized/status words as software guards around the polling driver.
 */

        .include "spi.S"

        .section .bss.spi_model, "aw", @nobits
        .balign 4
        .global spi_model_initialized
        .type   spi_model_initialized, @object
spi_model_initialized:
        .skip   4
        .size   spi_model_initialized, 4

        .global spi_model_clock_hz
        .type   spi_model_clock_hz, @object
spi_model_clock_hz:
        .skip   4
        .size   spi_model_clock_hz, 4

        .global spi_model_last_status
        .type   spi_model_last_status, @object
spi_model_last_status:
        .skip   4
        .size   spi_model_last_status, 4

        .global spi_model_transfer_count
        .type   spi_model_transfer_count, @object
spi_model_transfer_count:
        .skip   4
        .size   spi_model_transfer_count, 4

        .global spi_model_tx_log_len
        .type   spi_model_tx_log_len, @object
spi_model_tx_log_len:
        .skip   4
        .size   spi_model_tx_log_len, 4

        .global spi_model_force_timeout
        .type   spi_model_force_timeout, @object
spi_model_force_timeout:
        .skip   4
        .size   spi_model_force_timeout, 4

        .global spi_model_tx_log
        .type   spi_model_tx_log, @object
spi_model_tx_log:
        .skip   SPI_MAX_TRANSFER
        .size   spi_model_tx_log, SPI_MAX_TRANSFER

        .global spi_model_rx_source
        .type   spi_model_rx_source, @object
spi_model_rx_source:
        .skip   SPI_MAX_TRANSFER
        .size   spi_model_rx_source, SPI_MAX_TRANSFER
