# ============================================================================
# @function:    sx1262_init
# @module:      interface/lora
# @inputs:      a0 = timeout polls, or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       32
# @cycles:      bounded (reset plus 15 SPI command transfers)
# @ct:          not-required
# @spec:        milestone-8 sx1262-command-driver
# @verify:      proofs/lora/sx1262_init_contract.py
# @tests:       tests/interface/test_sx1262_init.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .macro SX1262_INIT_WRITE opcode, payload, length
        li      a0, \opcode
        la      a1, \payload
        li      a2, \length
        mv      a3, s0
        call    sx1262_command_write
        bnez    a0, .Lsx1262_init_error
        .endm

        .section .text.sx1262_init, "ax", @progbits
        .global sx1262_init
        .type   sx1262_init, @function
sx1262_init:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)

        mv      s0, a0
        bnez    s0, .Lsx1262_init_timeout_ready
        li      s0, SX1262_COMMAND_TIMEOUT_DEFAULT
.Lsx1262_init_timeout_ready:
        la      t0, sx1262_model_initialized
        sw      zero, 0(t0)
        la      t0, sx1262_model_init_error
        sw      zero, 0(t0)
        la      t0, sx1262_model_status_byte
        sw      zero, 0(t0)
        la      t0, sx1262_model_rx_armed
        sw      zero, 0(t0)

        call    spi_init
        beqz    a0, .Lsx1262_init_spi_ready
        li      t0, SPI_ERR_TIMEOUT
        beq     a0, t0, .Lsx1262_init_spi_timeout
        li      a0, LORA_ERR_SPI
        j       .Lsx1262_init_error

.Lsx1262_init_spi_ready:
        mv      a0, s0
        call    sx1262_reset
        bnez    a0, .Lsx1262_init_error

        li      a0, GPIO_LORA_DIO1_PIN
        call    gpio_config_input
        bnez    a0, .Lsx1262_init_gpio_error

        SX1262_INIT_WRITE SX1262_CMD_SET_STANDBY, .Lsx1262_init_p_standby, 1
        SX1262_INIT_WRITE SX1262_CMD_SET_REGULATOR_MODE, .Lsx1262_init_p_regulator, 1
        SX1262_INIT_WRITE SX1262_CMD_SET_DIO2_RF_SWITCH, .Lsx1262_init_p_dio2, 1
        SX1262_INIT_WRITE SX1262_CMD_SET_PA_CONFIG, .Lsx1262_init_p_pa, 4
        SX1262_INIT_WRITE SX1262_CMD_SET_RXTX_FALLBACK, .Lsx1262_init_p_fallback, 1
        SX1262_INIT_WRITE SX1262_CMD_CALIBRATE_IMAGE, .Lsx1262_init_p_cal_image, 2
        SX1262_INIT_WRITE SX1262_CMD_SET_PACKET_TYPE, .Lsx1262_init_p_packet_type, 1
        SX1262_INIT_WRITE SX1262_CMD_SET_RF_FREQUENCY, .Lsx1262_init_p_rf_freq, 4
        SX1262_INIT_WRITE SX1262_CMD_SET_TX_PARAMS, .Lsx1262_init_p_tx_params, 2
        SX1262_INIT_WRITE SX1262_CMD_SET_MOD_PARAMS, .Lsx1262_init_p_mod_params, 4
        SX1262_INIT_WRITE SX1262_CMD_SET_PACKET_PARAMS, .Lsx1262_init_p_packet_params, 6
        SX1262_INIT_WRITE SX1262_CMD_SET_BUFFER_BASE, .Lsx1262_init_p_buffer_base, 2
        SX1262_INIT_WRITE SX1262_CMD_CLEAR_IRQ_STATUS, .Lsx1262_init_p_irq_clear, 2
        SX1262_INIT_WRITE SX1262_CMD_SET_DIO_IRQ_PARAMS, .Lsx1262_init_p_dio_irq, 8

        li      a0, SX1262_CMD_GET_STATUS
        mv      a1, zero
        mv      a2, zero
        la      a3, sx1262_model_status_byte
        li      a4, 1
        mv      a5, s0
        call    sx1262_command_read
        bnez    a0, .Lsx1262_init_error

        la      t0, sx1262_model_initialized
        li      t1, 1
        sw      t1, 0(t0)
        la      t0, sx1262_model_init_error
        sw      zero, 0(t0)
        li      a0, LORA_OK
        j       .Lsx1262_init_return

.Lsx1262_init_gpio_error:
        li      a0, LORA_ERR_GPIO
        j       .Lsx1262_init_error

.Lsx1262_init_spi_timeout:
        li      a0, LORA_ERR_SPI_TIMEOUT

.Lsx1262_init_error:
        la      t0, sx1262_model_init_error
        sw      a0, 0(t0)

.Lsx1262_init_return:
        lw      s1, 20(sp)
        lw      s0, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   sx1262_init, . - sx1262_init

        .section .rodata.sx1262_init, "a", @progbits
        .balign 1
.Lsx1262_init_p_standby:
        .byte   SX1262_STANDBY_RC
.Lsx1262_init_p_regulator:
        .byte   SX1262_REGULATOR_DCDC
.Lsx1262_init_p_dio2:
        .byte   SX1262_DIO2_RF_SWITCH_ENABLE
.Lsx1262_init_p_pa:
        .byte   SX1262_PA_DUTY_CYCLE, SX1262_PA_HP_MAX
        .byte   SX1262_PA_DEVICE_SEL_SX1262, SX1262_PA_LUT
.Lsx1262_init_p_fallback:
        .byte   SX1262_FALLBACK_STDBY_RC
.Lsx1262_init_p_cal_image:
        .byte   SX1262_IMAGE_CAL_863_870_1, SX1262_IMAGE_CAL_863_870_2
.Lsx1262_init_p_packet_type:
        .byte   SX1262_PACKET_TYPE_LORA
.Lsx1262_init_p_rf_freq:
        .byte   0x36, 0x33, 0x33, 0x33
.Lsx1262_init_p_tx_params:
        .byte   SX1262_BENCH_TX_POWER_DBM, SX1262_RAMP_200_US
.Lsx1262_init_p_mod_params:
        .byte   SX1262_LORA_SF8, SX1262_LORA_BW_125_KHZ
        .byte   SX1262_LORA_CR_4_5, SX1262_LORA_LDRO_OFF
.Lsx1262_init_p_packet_params:
        .byte   0x00, SX1262_BENCH_PREAMBLE_SYMBOLS
        .byte   SX1262_LORA_HEADER_EXPLICIT, SX1262_BENCH_PAYLOAD_MAX
        .byte   SX1262_LORA_CRC_ON, SX1262_LORA_IQ_STANDARD
.Lsx1262_init_p_buffer_base:
        .byte   0x00, 0x00
.Lsx1262_init_p_irq_clear:
        .byte   0xff, 0xff
.Lsx1262_init_p_dio_irq:
        .byte   0x02, 0x63, 0x02, 0x63
        .byte   0x00, 0x00, 0x00, 0x00
