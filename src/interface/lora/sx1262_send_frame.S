# ============================================================================
# @function:    sx1262_send_frame
# @module:      interface/lora
# @inputs:      a0 = frame ptr, a1 = frame len, a2 = timeout polls or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       64
# @cycles:      bounded (<=254 frame bytes + command transfers + TX IRQ polls)
# @ct:          not-required
# @spec:        milestone-8 lora-packet-txrx
# @verify:      proofs/lora/sx1262_send_frame_contract.py
# @tests:       tests/interface/test_sx1262_send_frame.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.sx1262_send_frame, "ax", @progbits
        .global sx1262_send_frame
        .type   sx1262_send_frame, @function
sx1262_send_frame:
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

        mv      s0, a0                  /* frame ptr */
        mv      s1, a1                  /* frame len */
        mv      s2, a2                  /* timeout polls */
        bnez    s2, .Lsx1262_send_timeout_ready
        li      s2, SX1262_TX_TIMEOUT_DEFAULT
.Lsx1262_send_timeout_ready:
        la      t0, sx1262_model_tx_len
        sw      zero, 0(t0)
        la      t0, sx1262_model_last_irq
        sw      zero, 0(t0)

        la      t0, sx1262_model_initialized
        lw      t1, 0(t0)
        beqz    t1, .Lsx1262_send_not_initialized
        beqz    s0, .Lsx1262_send_invalid
        beqz    s1, .Lsx1262_send_invalid
        li      t0, SX1262_BENCH_PAYLOAD_MAX
        bgtu    s1, t0, .Lsx1262_send_overflow

        la      s3, sx1262_frame_tx_buf
        sb      zero, 0(s3)             /* FIFO offset */
        addi    t0, s3, 1
        mv      t1, s0
        mv      t2, s1
.Lsx1262_send_copy_loop:
        beqz    t2, .Lsx1262_send_copy_done
        lbu     t3, 0(t1)
        sb      t3, 0(t0)
        addi    t1, t1, 1
        addi    t0, t0, 1
        addi    t2, t2, -1
        j       .Lsx1262_send_copy_loop

.Lsx1262_send_copy_done:
        la      s4, sx1262_tx_packet_params_buf
        sb      zero, 0(s4)
        li      t0, SX1262_BENCH_PREAMBLE_SYMBOLS
        sb      t0, 1(s4)
        li      t0, SX1262_LORA_HEADER_EXPLICIT
        sb      t0, 2(s4)
        sb      s1, 3(s4)
        li      t0, SX1262_LORA_CRC_ON
        sb      t0, 4(s4)
        li      t0, SX1262_LORA_IQ_STANDARD
        sb      t0, 5(s4)

        li      a0, SX1262_CMD_SET_PACKET_PARAMS
        mv      a1, s4
        li      a2, 6
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_send_return

        li      a0, SX1262_CMD_WRITE_BUFFER
        mv      a1, s3
        addi    a2, s1, 1
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_send_return

        li      a0, SX1262_CMD_CLEAR_IRQ_STATUS
        la      a1, .Lsx1262_send_p_irq_clear
        li      a2, 2
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_send_return

        li      a0, SX1262_CMD_SET_TX
        la      a1, .Lsx1262_send_p_tx_timeout
        li      a2, 3
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_send_return

        mv      s5, s2
.Lsx1262_send_poll_loop:
        li      a0, SX1262_CMD_GET_IRQ_STATUS
        mv      a1, zero
        mv      a2, zero
        la      a3, sx1262_irq_read_buf
        li      a4, 2
        mv      a5, s2
        call    sx1262_command_read
        bnez    a0, .Lsx1262_send_return

        la      t0, sx1262_irq_read_buf
        lbu     t1, 0(t0)
        lbu     t2, 1(t0)
        slli    t1, t1, 8
        or      s6, t1, t2
        la      t0, sx1262_model_last_irq
        sw      s6, 0(t0)

        li      t0, SX1262_IRQ_TX_DONE
        and     t1, s6, t0
        bnez    t1, .Lsx1262_send_tx_done
        li      t0, SX1262_IRQ_TIMEOUT
        and     t1, s6, t0
        bnez    t1, .Lsx1262_send_tx_timeout
        beqz    s5, .Lsx1262_send_tx_timeout
        addi    s5, s5, -1
        li      a0, SX1262_TX_POLL_DELAY_US
        call    clock_delay_us
        j       .Lsx1262_send_poll_loop

.Lsx1262_send_tx_done:
        li      a0, SX1262_CMD_CLEAR_IRQ_STATUS
        la      a1, .Lsx1262_send_p_irq_clear
        li      a2, 2
        mv      a3, s2
        call    sx1262_command_write
        bnez    a0, .Lsx1262_send_return
        la      t0, sx1262_model_tx_len
        sw      s1, 0(t0)
        li      a0, LORA_OK
        j       .Lsx1262_send_return

.Lsx1262_send_invalid:
        li      a0, LORA_ERR_INVAL
        j       .Lsx1262_send_return

.Lsx1262_send_not_initialized:
        li      a0, LORA_ERR_NOT_INITIALIZED
        j       .Lsx1262_send_return

.Lsx1262_send_overflow:
        li      a0, LORA_ERR_OVERFLOW
        j       .Lsx1262_send_return

.Lsx1262_send_tx_timeout:
        li      a0, LORA_ERR_TX_TIMEOUT

.Lsx1262_send_return:
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

        .size   sx1262_send_frame, . - sx1262_send_frame

        .section .rodata.sx1262_send_frame, "a", @progbits
        .balign 1
.Lsx1262_send_p_irq_clear:
        .byte   0xff, 0xff
.Lsx1262_send_p_tx_timeout:
        .byte   0x00, 0x00, 0x00
