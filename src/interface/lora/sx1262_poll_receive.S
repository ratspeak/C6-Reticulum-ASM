# ============================================================================
# @function:    sx1262_poll_receive
# @module:      interface/lora
# @inputs:      a0 = output ptr, a1 = output capacity, a2 = timeout polls or 0 for default
# @outputs:     a0 = received length on success, or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       80
# @cycles:      bounded (<=253 RX bytes + command transfers)
# @ct:          not-required
# @spec:        milestone-8 lora-packet-txrx
# @verify:      proofs/lora/sx1262_poll_receive_contract.py
# @tests:       tests/interface/test_sx1262_poll_receive.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.sx1262_poll_receive, "ax", @progbits
        .global sx1262_poll_receive
        .type   sx1262_poll_receive, @function
sx1262_poll_receive:
        addi    sp, sp, -80
        sw      ra, 76(sp)
        sw      s0, 72(sp)
        sw      s1, 68(sp)
        sw      s2, 64(sp)
        sw      s3, 60(sp)
        sw      s4, 56(sp)
        sw      s5, 52(sp)
        sw      s6, 48(sp)
        sw      s7, 44(sp)
        sw      s8, 40(sp)
        sw      s9, 36(sp)

        mv      s0, a0                  /* output ptr */
        mv      s1, a1                  /* output capacity */
        mv      s2, a2                  /* command timeout polls */
        bnez    s2, .Lsx1262_poll_timeout_ready
        li      s2, SX1262_COMMAND_TIMEOUT_DEFAULT
.Lsx1262_poll_timeout_ready:
        la      t0, sx1262_model_rx_len
        sw      zero, 0(t0)
        la      t0, sx1262_model_last_irq
        sw      zero, 0(t0)

        la      t0, sx1262_model_initialized
        lw      t1, 0(t0)
        beqz    t1, .Lsx1262_poll_not_initialized
        beqz    s0, .Lsx1262_poll_invalid
        beqz    s1, .Lsx1262_poll_invalid

        li      a0, GPIO_LORA_DIO1_PIN
        call    gpio_config_input
        bnez    a0, .Lsx1262_poll_gpio_error

        li      a0, GPIO_LORA_DIO1_PIN
        call    gpio_read
        bltz    a0, .Lsx1262_poll_gpio_error
        beqz    a0, .Lsx1262_poll_arm_rx_no_packet

        li      a0, SX1262_CMD_GET_IRQ_STATUS
        mv      a1, zero
        mv      a2, zero
        la      a3, sx1262_irq_read_buf
        li      a4, 2
        mv      a5, s2
        call    sx1262_command_read
        bnez    a0, .Lsx1262_poll_return

        la      t0, sx1262_irq_read_buf
        lbu     t1, 0(t0)
        lbu     t2, 1(t0)
        slli    t1, t1, 8
        or      s3, t1, t2              /* irq status */
        la      t0, sx1262_model_last_irq
        sw      s3, 0(t0)

        li      t0, SX1262_IRQ_HEADER_ERR
        li      t1, SX1262_IRQ_CRC_ERR
        or      t0, t0, t1
        and     t0, s3, t0
        bnez    t0, .Lsx1262_poll_clear_then_crc

        li      t0, SX1262_IRQ_TIMEOUT
        and     t0, s3, t0
        bnez    t0, .Lsx1262_poll_clear_then_no_packet

        li      t0, SX1262_IRQ_RX_DONE
        and     t0, s3, t0
        beqz    t0, .Lsx1262_poll_clear_then_no_packet

        li      a0, SX1262_CMD_GET_RX_BUFFER_STATUS
        la      a1, .Lsx1262_poll_p_skip_status
        li      a2, 1
        la      a3, sx1262_rx_status_buf
        li      a4, 2
        mv      a5, s2
        call    sx1262_command_read
        bnez    a0, .Lsx1262_poll_return

        la      t0, sx1262_rx_status_buf
        lbu     s4, 0(t0)               /* payload length */
        lbu     s5, 1(t0)               /* RX buffer pointer */
        beqz    s4, .Lsx1262_poll_clear_then_no_packet
        bgtu    s4, s1, .Lsx1262_poll_clear_then_overflow
        li      t0, SX1262_BENCH_PAYLOAD_MAX
        bgtu    s4, t0, .Lsx1262_poll_clear_then_overflow

        la      s6, sx1262_read_buffer_req_buf
        sb      s5, 0(s6)
        sb      zero, 1(s6)
        li      a0, SX1262_CMD_READ_BUFFER
        mv      a1, s6
        li      a2, 2
        la      a3, sx1262_frame_rx_buf
        mv      a4, s4
        mv      a5, s2
        call    sx1262_command_read
        bnez    a0, .Lsx1262_poll_return

        la      t0, sx1262_frame_rx_buf
        mv      t1, s0
        mv      t2, s4
.Lsx1262_poll_copy_loop:
        beqz    t2, .Lsx1262_poll_copy_done
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       .Lsx1262_poll_copy_loop

.Lsx1262_poll_copy_done:
        la      t0, sx1262_model_rx_len
        sw      s4, 0(t0)
        mv      s7, s4
        j       .Lsx1262_poll_clear_then_s7

.Lsx1262_poll_arm_rx_no_packet:
        li      s7, LORA_ERR_NO_PACKET
        j       .Lsx1262_poll_set_rx_then_s7

.Lsx1262_poll_clear_then_crc:
        li      s7, LORA_ERR_CRC
        j       .Lsx1262_poll_clear_then_s7
.Lsx1262_poll_clear_then_no_packet:
        li      s7, LORA_ERR_NO_PACKET
        j       .Lsx1262_poll_clear_then_s7
.Lsx1262_poll_clear_then_overflow:
        li      s7, LORA_ERR_OVERFLOW

.Lsx1262_poll_clear_then_s7:
        li      a0, SX1262_CMD_CLEAR_IRQ_STATUS
        la      a1, .Lsx1262_poll_p_irq_clear
        li      a2, 2
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_poll_return

.Lsx1262_poll_set_rx_then_s7:
        li      a0, SX1262_CMD_SET_RX
        la      a1, .Lsx1262_poll_p_rx_continuous
        li      a2, 3
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_poll_return
        mv      a0, s7
        j       .Lsx1262_poll_return

.Lsx1262_poll_invalid:
        li      a0, LORA_ERR_INVAL
        j       .Lsx1262_poll_return

.Lsx1262_poll_not_initialized:
        li      a0, LORA_ERR_NOT_INITIALIZED
        j       .Lsx1262_poll_return

.Lsx1262_poll_gpio_error:
        li      a0, LORA_ERR_GPIO

.Lsx1262_poll_return:
        lw      s9, 36(sp)
        lw      s8, 40(sp)
        lw      s7, 44(sp)
        lw      s6, 48(sp)
        lw      s5, 52(sp)
        lw      s4, 56(sp)
        lw      s3, 60(sp)
        lw      s2, 64(sp)
        lw      s1, 68(sp)
        lw      s0, 72(sp)
        lw      ra, 76(sp)
        addi    sp, sp, 80
        ret

        .size   sx1262_poll_receive, . - sx1262_poll_receive

        .section .rodata.sx1262_poll_receive, "a", @progbits
        .balign 1
.Lsx1262_poll_p_skip_status:
        .byte   0x00
.Lsx1262_poll_p_irq_clear:
        .byte   0xff, 0xff
.Lsx1262_poll_p_rx_continuous:
        .byte   (SX1262_RX_CONTINUOUS_TIMEOUT >> 16) & 0xff
        .byte   (SX1262_RX_CONTINUOUS_TIMEOUT >> 8) & 0xff
        .byte   SX1262_RX_CONTINUOUS_TIMEOUT & 0xff
