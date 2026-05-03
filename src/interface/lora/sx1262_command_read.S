# ============================================================================
# @function:    sx1262_command_read
# @module:      interface/lora
# @inputs:      a0 = opcode, a1 = request ptr or 0, a2 = request len, a3 = rx ptr, a4 = rx len, a5 = timeout polls or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       64
# @cycles:      bounded (<=256 SPI bytes plus timeout polls)
# @ct:          not-required
# @spec:        milestone-8 sx1262-command-driver
# @verify:      proofs/lora/sx1262_command_contract.py
# @tests:       tests/interface/test_sx1262_commands.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.sx1262_command_read, "ax", @progbits
        .global sx1262_command_read
        .type   sx1262_command_read, @function
sx1262_command_read:
        addi    sp, sp, -64
        sw      ra, 60(sp)
        sw      s0, 56(sp)
        sw      s1, 52(sp)
        sw      s2, 48(sp)
        sw      s3, 44(sp)
        sw      s4, 40(sp)
        sw      s5, 36(sp)
        sw      s6, 32(sp)
        sw      s7, 28(sp)
        sw      s8, 24(sp)
        sw      s9, 20(sp)

        mv      s0, a0                  /* opcode */
        mv      s1, a1                  /* request ptr */
        mv      s2, a2                  /* request len */
        mv      s3, a3                  /* caller rx ptr */
        mv      s4, a4                  /* caller rx len */
        mv      s5, a5                  /* timeout polls */
        bnez    s5, .Lsx1262_cmdr_timeout_ready
        li      s5, SX1262_COMMAND_TIMEOUT_DEFAULT
.Lsx1262_cmdr_timeout_ready:
        li      t0, 255
        bgtu    s0, t0, .Lsx1262_cmdr_invalid
        li      t0, SPI_MAX_TRANSFER
        bgtu    s2, t0, .Lsx1262_cmdr_invalid
        bgtu    s4, t0, .Lsx1262_cmdr_invalid
        beqz    s4, .Lsx1262_cmdr_invalid
        beqz    s3, .Lsx1262_cmdr_invalid
        beqz    s2, .Lsx1262_cmdr_have_ptrs
        beqz    s1, .Lsx1262_cmdr_invalid
.Lsx1262_cmdr_have_ptrs:
        addi    s8, s2, 1
        add     s8, s8, s4
        li      t0, SPI_MAX_TRANSFER
        bgtu    s8, t0, .Lsx1262_cmdr_invalid

        li      a0, GPIO_LORA_NSS_PIN
        call    gpio_config_output
        bnez    a0, .Lsx1262_cmdr_gpio_error

        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_config_input
        bnez    a0, .Lsx1262_cmdr_gpio_error

        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_cmdr_gpio_error

        mv      s9, s5
.Lsx1262_cmdr_busy_loop:
        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_read
        bltz    a0, .Lsx1262_cmdr_gpio_error
        beqz    a0, .Lsx1262_cmdr_busy_ready
        beqz    s9, .Lsx1262_cmdr_busy_timeout
        addi    s9, s9, -1
        li      a0, SX1262_BUSY_POLL_DELAY_US
        call    clock_delay_us
        j       .Lsx1262_cmdr_busy_loop

.Lsx1262_cmdr_busy_ready:
        la      s6, sx1262_command_tx_buf
        la      s7, sx1262_command_rx_buf
        sb      s0, 0(s6)
        addi    t0, s6, 1
        mv      t1, s1
        mv      t2, s2
.Lsx1262_cmdr_request_loop:
        beqz    t2, .Lsx1262_cmdr_request_done
        lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t1, t1, 1
        addi    t0, t0, 1
        addi    t2, t2, -1
        j       .Lsx1262_cmdr_request_loop

.Lsx1262_cmdr_request_done:
        mv      t2, s4
.Lsx1262_cmdr_dummy_loop:
        beqz    t2, .Lsx1262_cmdr_dummy_done
        sb      zero, 0(t0)
        addi    t0, t0, 1
        addi    t2, t2, -1
        j       .Lsx1262_cmdr_dummy_loop

.Lsx1262_cmdr_dummy_done:
        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 0
        call    gpio_write
        bnez    a0, .Lsx1262_cmdr_gpio_error

        mv      a0, s6
        mv      a1, s7
        mv      a2, s8
        mv      a3, s5
        call    spi_transfer
        mv      s9, a0

        li      a0, GPIO_LORA_NSS_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_cmdr_gpio_error

        beqz    s9, .Lsx1262_cmdr_copy_response
        li      t0, SPI_ERR_TIMEOUT
        beq     s9, t0, .Lsx1262_cmdr_spi_timeout
        li      a0, LORA_ERR_SPI
        j       .Lsx1262_cmdr_return

.Lsx1262_cmdr_copy_response:
        addi    t0, s7, 1
        add     t0, t0, s2
        mv      t1, s3
        mv      t2, s4
.Lsx1262_cmdr_response_loop:
        beqz    t2, .Lsx1262_cmdr_ok
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lsx1262_cmdr_response_loop

.Lsx1262_cmdr_ok:
        li      a0, LORA_OK
        j       .Lsx1262_cmdr_return

.Lsx1262_cmdr_invalid:
        li      a0, LORA_ERR_INVAL
        j       .Lsx1262_cmdr_return

.Lsx1262_cmdr_gpio_error:
        li      a0, LORA_ERR_GPIO
        j       .Lsx1262_cmdr_return

.Lsx1262_cmdr_busy_timeout:
        li      a0, LORA_ERR_BUSY_TIMEOUT
        j       .Lsx1262_cmdr_return

.Lsx1262_cmdr_spi_timeout:
        li      a0, LORA_ERR_SPI_TIMEOUT

.Lsx1262_cmdr_return:
        lw      s9, 20(sp)
        lw      s8, 24(sp)
        lw      s7, 28(sp)
        lw      s6, 32(sp)
        lw      s5, 36(sp)
        lw      s4, 40(sp)
        lw      s3, 44(sp)
        lw      s2, 48(sp)
        lw      s1, 52(sp)
        lw      s0, 56(sp)
        lw      ra, 60(sp)
        addi    sp, sp, 64
        ret

        .size   sx1262_command_read, . - sx1262_command_read
