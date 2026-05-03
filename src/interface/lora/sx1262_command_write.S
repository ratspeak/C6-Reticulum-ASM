# ============================================================================
# @function:    sx1262_command_write
# @module:      interface/lora
# @inputs:      a0 = opcode, a1 = payload ptr or 0, a2 = payload len, a3 = timeout polls or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a3, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       48
# @cycles:      bounded (<=256 SPI bytes plus timeout polls)
# @ct:          not-required
# @spec:        milestone-8 sx1262-command-driver
# @verify:      proofs/lora/sx1262_command_contract.py
# @tests:       tests/interface/test_sx1262_commands.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.sx1262_command_write, "ax", @progbits
        .global sx1262_command_write
        .type   sx1262_command_write, @function
sx1262_command_write:
        addi    sp, sp, -48
        sw      ra, 44(sp)
        sw      s0, 40(sp)
        sw      s1, 36(sp)
        sw      s2, 32(sp)
        sw      s3, 28(sp)
        sw      s4, 24(sp)
        sw      s5, 20(sp)
        sw      s6, 16(sp)

        mv      s0, a0                  /* opcode */
        mv      s1, a1                  /* payload ptr */
        mv      s2, a2                  /* payload len */
        mv      s3, a3                  /* timeout polls */
        bnez    s3, .Lsx1262_cmdw_timeout_ready
        li      s3, SX1262_COMMAND_TIMEOUT_DEFAULT
.Lsx1262_cmdw_timeout_ready:
        li      t0, 255
        bgtu    s0, t0, .Lsx1262_cmdw_invalid
        li      t0, SPI_MAX_TRANSFER - 1
        bgtu    s2, t0, .Lsx1262_cmdw_invalid
        beqz    s2, .Lsx1262_cmdw_args_ok
        beqz    s1, .Lsx1262_cmdw_invalid

.Lsx1262_cmdw_args_ok:
        li      a0, GPIO_LORA_NSS_PIN
        call    gpio_config_output
        bnez    a0, .Lsx1262_cmdw_gpio_error

        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_config_input
        bnez    a0, .Lsx1262_cmdw_gpio_error

        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_cmdw_gpio_error

        mv      s4, s3
.Lsx1262_cmdw_busy_loop:
        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_read
        bltz    a0, .Lsx1262_cmdw_gpio_error
        beqz    a0, .Lsx1262_cmdw_busy_ready
        beqz    s4, .Lsx1262_cmdw_busy_timeout
        addi    s4, s4, -1
        li      a0, SX1262_BUSY_POLL_DELAY_US
        call    clock_delay_us
        j       .Lsx1262_cmdw_busy_loop

.Lsx1262_cmdw_busy_ready:
        la      s5, sx1262_command_tx_buf
        sb      s0, 0(s5)
        addi    t0, s5, 1
        mv      t1, s1
        mv      t2, s2
.Lsx1262_cmdw_copy_loop:
        beqz    t2, .Lsx1262_cmdw_copy_done
        lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t1, t1, 1
        addi    t0, t0, 1
        addi    t2, t2, -1
        j       .Lsx1262_cmdw_copy_loop

.Lsx1262_cmdw_copy_done:
        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 0
        call    gpio_write
        bnez    a0, .Lsx1262_cmdw_gpio_error

        mv      a0, s5
        mv      a1, zero
        addi    a2, s2, 1
        mv      a3, s3
        call    spi_transfer
        mv      s6, a0

        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_cmdw_gpio_error

        beqz    s6, .Lsx1262_cmdw_ok
        li      t0, SPI_ERR_TIMEOUT
        beq     s6, t0, .Lsx1262_cmdw_spi_timeout
        li      a0, LORA_ERR_SPI
        j       .Lsx1262_cmdw_return

.Lsx1262_cmdw_ok:
        li      a0, LORA_OK
        j       .Lsx1262_cmdw_return

.Lsx1262_cmdw_invalid:
        li      a0, LORA_ERR_INVAL
        j       .Lsx1262_cmdw_return

.Lsx1262_cmdw_gpio_error:
        li      a0, LORA_ERR_GPIO
        j       .Lsx1262_cmdw_return

.Lsx1262_cmdw_busy_timeout:
        li      a0, LORA_ERR_BUSY_TIMEOUT
        j       .Lsx1262_cmdw_return

.Lsx1262_cmdw_spi_timeout:
        li      a0, LORA_ERR_SPI_TIMEOUT

.Lsx1262_cmdw_return:
        lw      s6, 16(sp)
        lw      s5, 20(sp)
        lw      s4, 24(sp)
        lw      s3, 28(sp)
        lw      s2, 32(sp)
        lw      s1, 36(sp)
        lw      s0, 40(sp)
        lw      ra, 44(sp)
        addi    sp, sp, 48
        ret

        .size   sx1262_command_write, . - sx1262_command_write
