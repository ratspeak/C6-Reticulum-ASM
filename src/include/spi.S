/* SPI helper constants for milestone-8 LoRa/SX1262 traffic. */

        .include "gpio.S"

        .equ SPI_OK,                    0
        .equ SPI_ERR_INVAL,            -1
        .equ SPI_ERR_OVERFLOW,         -2
        .equ SPI_ERR_TIMEOUT,          -3

        .equ SPI_DEFAULT_HZ,            1000000
        .equ SPI_MAX_TRANSFER,          256
        .equ SPI_C6_CHUNK_BYTES,        64

        /* ESP32-C6 SPI2/GPIO-matrix register addresses sourced from ESP-IDF
         * v6.0 components/{soc,esp_hal_gpspi,esp_hal_gpio} headers. */
        .equ C6_SPI2_BASE,              0x60081000
        .equ C6_SPI2_CMD,               C6_SPI2_BASE + 0x00
        .equ C6_SPI2_CLOCK,             C6_SPI2_BASE + 0x0c
        .equ C6_SPI2_USER,              C6_SPI2_BASE + 0x10
        .equ C6_SPI2_MS_DLEN,           C6_SPI2_BASE + 0x1c
        .equ C6_SPI2_MISC,              C6_SPI2_BASE + 0x20
        .equ C6_SPI2_DMA_CONF,          C6_SPI2_BASE + 0x30
        .equ C6_SPI2_DMA_INT_ENA,       C6_SPI2_BASE + 0x34
        .equ C6_SPI2_DMA_INT_CLR,       C6_SPI2_BASE + 0x38
        .equ C6_SPI2_DMA_INT_RAW,       C6_SPI2_BASE + 0x3c
        .equ C6_SPI2_W0,                C6_SPI2_BASE + 0x98
        .equ C6_SPI2_SLAVE,             C6_SPI2_BASE + 0xe0
        .equ C6_SPI2_CLK_GATE,          C6_SPI2_BASE + 0xe8

        .equ C6_PCR_BASE,               0x60096000
        .equ C6_PCR_SPI2_CONF,          C6_PCR_BASE + 0xc0
        .equ C6_PCR_SPI2_CLKM_CONF,     C6_PCR_BASE + 0xc4
        .equ C6_PCR_SPI2_CLK_EN,        0x00000001
        .equ C6_PCR_SPI2_CLKM_EN,       0x00400000

        .equ C6_GPIO_FUNC_IN_SEL_BASE,  C6_GPIO_BASE + 0x154

        .equ C6_SPI_USR,                0x01000000
        .equ C6_SPI_UPDATE,             0x00800000
        .equ C6_SPI_DOUTDIN,            0x00000001
        .equ C6_SPI_USR_MOSI,           0x08000000
        .equ C6_SPI_USR_MISO,           0x10000000
        .equ C6_SPI_USER_MOSI_VALUE,    0x08000001
        .equ C6_SPI_TRANS_DONE,         0x00001000
        .equ C6_SPI_BUF_AFIFO_RST,      0x40000000
        .equ C6_SPI_RX_AFIFO_RST,       0x20000000
        .equ C6_SPI_AFIFO_RST_MASK,     0x60000000
        .equ C6_SPI_CLOCK_1MHZ_XTAL,    0x000274e7
        .equ C6_SPI_CLK_GATE_ON,        0x00000003

        .equ C6_SPI_SCK_PIN,            21
        .equ C6_SPI_MOSI_PIN,           22
        .equ C6_SPI_MISO_PIN,           23
        .equ C6_SPI_PIN_MASK,           0x00e00000
        .equ C6_SPI_OUTPUT_MASK,        0x00600000
        .equ C6_SPI_INPUT_MASK,         0x00800000

        .equ C6_FSPICLK_OUT_IDX,        63
        .equ C6_FSPIQ_IN_IDX,           64
        .equ C6_FSPID_OUT_IDX,          65
        .equ C6_GPIO_SIG_IN_FROM_MATRIX, 0x00000080
