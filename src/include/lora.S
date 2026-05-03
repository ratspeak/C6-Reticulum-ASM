/* SX1262/LoRa interface constants for milestone 8. */

        .include "spi.S"

        .equ LORA_OK,                       0
        .equ LORA_ERR_GPIO,                -1
        .equ LORA_ERR_BUSY_TIMEOUT,        -2
        .equ LORA_ERR_INVAL,               -3
        .equ LORA_ERR_SPI_TIMEOUT,         -4
        .equ LORA_ERR_SPI,                 -5
        .equ LORA_ERR_OVERFLOW,            -6
        .equ LORA_ERR_TX_TIMEOUT,          -7
        .equ LORA_ERR_NO_PACKET,           -8
        .equ LORA_ERR_CRC,                 -9
        .equ LORA_ERR_NOT_INITIALIZED,     -10

        .equ SX1262_RESET_LOW_US,           100
        .equ SX1262_RESET_SETTLE_US,        100
        .equ SX1262_BUSY_POLL_DELAY_US,     10
        .equ SX1262_BUSY_TIMEOUT_DEFAULT,   10000
        .equ SX1262_COMMAND_TIMEOUT_DEFAULT, 10000
        .equ SX1262_TX_TIMEOUT_DEFAULT,     10000
        .equ SX1262_TX_POLL_DELAY_US,       1000

        .equ SX1262_CMD_CLEAR_IRQ_STATUS,   0x02
        .equ SX1262_CMD_SET_DIO_IRQ_PARAMS, 0x08
        .equ SX1262_CMD_WRITE_BUFFER,       0x0e
        .equ SX1262_CMD_GET_IRQ_STATUS,     0x12
        .equ SX1262_CMD_GET_RX_BUFFER_STATUS, 0x13
        .equ SX1262_CMD_READ_BUFFER,        0x1e
        .equ SX1262_CMD_GET_STATUS,         0xc0
        .equ SX1262_CMD_SET_STANDBY,        0x80
        .equ SX1262_CMD_SET_RX,             0x82
        .equ SX1262_CMD_SET_TX,             0x83
        .equ SX1262_CMD_SET_REGULATOR_MODE, 0x96
        .equ SX1262_CMD_CALIBRATE_IMAGE,    0x98
        .equ SX1262_CMD_SET_DIO2_RF_SWITCH, 0x9d
        .equ SX1262_CMD_SET_PA_CONFIG,      0x95
        .equ SX1262_CMD_SET_RXTX_FALLBACK,  0x93
        .equ SX1262_CMD_SET_RF_FREQUENCY,   0x86
        .equ SX1262_CMD_SET_PACKET_TYPE,    0x8a
        .equ SX1262_CMD_SET_TX_PARAMS,      0x8e
        .equ SX1262_CMD_SET_MOD_PARAMS,     0x8b
        .equ SX1262_CMD_SET_PACKET_PARAMS,  0x8c
        .equ SX1262_CMD_SET_BUFFER_BASE,    0x8f

        .equ SX1262_STANDBY_RC,             0x00
        .equ SX1262_REGULATOR_DCDC,         0x01
        .equ SX1262_DIO2_RF_SWITCH_ENABLE,  0x01
        .equ SX1262_FALLBACK_STDBY_RC,      0x20
        .equ SX1262_PACKET_TYPE_LORA,       0x01

        .equ SX1262_BENCH_FREQUENCY_HZ,     867200000
        .equ SX1262_BENCH_RF_FREQ_WORD,     0x36333333
        .equ SX1262_BENCH_TX_POWER_DBM,     7
        .equ SX1262_BENCH_PREAMBLE_SYMBOLS, 12
        .equ SX1262_BENCH_PAYLOAD_MAX,      253

        .equ SX1262_PA_DUTY_CYCLE,          0x04
        .equ SX1262_PA_HP_MAX,              0x07
        .equ SX1262_PA_DEVICE_SEL_SX1262,   0x00
        .equ SX1262_PA_LUT,                 0x01
        .equ SX1262_RAMP_200_US,            0x04
        .equ SX1262_LORA_SF8,               0x08
        .equ SX1262_LORA_BW_125_KHZ,        0x04
        .equ SX1262_LORA_CR_4_5,            0x01
        .equ SX1262_LORA_LDRO_OFF,          0x00
        .equ SX1262_LORA_HEADER_EXPLICIT,   0x00
        .equ SX1262_LORA_CRC_ON,            0x01
        .equ SX1262_LORA_IQ_STANDARD,       0x00
        .equ SX1262_IMAGE_CAL_863_870_1,    0xd7
        .equ SX1262_IMAGE_CAL_863_870_2,    0xdb
        .equ SX1262_IRQ_MASK_BENCH,         0x0263
        .equ SX1262_IRQ_TX_DONE,            0x0001
        .equ SX1262_IRQ_RX_DONE,            0x0002
        .equ SX1262_IRQ_HEADER_ERR,         0x0020
        .equ SX1262_IRQ_CRC_ERR,            0x0040
        .equ SX1262_IRQ_TIMEOUT,            0x0200
        .equ SX1262_RX_CONTINUOUS_TIMEOUT,  0xffffff
