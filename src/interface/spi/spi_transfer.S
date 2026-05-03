# ============================================================================
# @function:    spi_transfer
# @module:      interface/spi
# @inputs:      a0 = tx buffer or 0, a1 = rx buffer or 0, a2 = length, a3 = timeout polls
# @outputs:     a0 = SPI_OK or negative SPI_ERR_*
# @clobbers:    a0..a7, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       0
# @cycles:      bounded (~64 byte chunks plus timeout polls)
# @ct:          not-required
# @spec:        milestone-8 spi-transfer-path
# @verify:      proofs/spi/spi_contract.py
# @tests:       tests/interface/test_spi_helpers.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "spi.S"

        .section .text.spi_transfer, "ax", @progbits
        .global spi_transfer
        .type   spi_transfer, @function
spi_transfer:
        beqz    a2, .Lspi_transfer_zero

        li      t0, SPI_MAX_TRANSFER
        bgtu    a2, t0, .Lspi_transfer_overflow

        la      t0, spi_model_initialized
        lw      t1, 0(t0)
        beqz    t1, .Lspi_transfer_invalid

        or      t0, a0, a1
        beqz    t0, .Lspi_transfer_invalid

        beqz    a3, .Lspi_transfer_timeout

        la      t0, spi_model_force_timeout
        lw      t1, 0(t0)
        bnez    t1, .Lspi_transfer_timeout

        .ifdef TARGET_C6
        mv      a4, a0                  /* current tx pointer, or 0 */
        mv      a5, a1                  /* current rx pointer, or 0 */
        mv      a6, a2                  /* remaining bytes */
        mv      a7, a3                  /* per-register wait budget */

.Lspi_transfer_c6_chunk:
        li      t0, SPI_C6_CHUNK_BYTES
        bltu    a6, t0, .Lspi_transfer_c6_small
        mv      t1, t0
        j       .Lspi_transfer_c6_have_chunk
.Lspi_transfer_c6_small:
        mv      t1, a6
.Lspi_transfer_c6_have_chunk:
        li      t0, C6_SPI2_DMA_CONF
        li      t2, C6_SPI_AFIFO_RST_MASK
        sw      t2, 0(t0)
        sw      zero, 0(t0)

        li      t0, C6_SPI2_W0
        li      t2, 16
.Lspi_transfer_c6_clear_buf:
        sw      zero, 0(t0)
        addi    t0, t0, 4
        addi    t2, t2, -1
        bnez    t2, .Lspi_transfer_c6_clear_buf

        beqz    a4, .Lspi_transfer_c6_pack_done
        li      t0, C6_SPI2_W0
        mv      t2, zero                /* packed word */
        mv      t3, zero                /* bytes in current word */
        mv      t4, zero                /* bytes copied */
        mv      t6, zero                /* shift */
.Lspi_transfer_c6_pack_loop:
        beq     t4, t1, .Lspi_transfer_c6_pack_finish
        lbu     t5, 0(a4)
        sll     t5, t5, t6
        or      t2, t2, t5
        addi    a4, a4, 1
        addi    t4, t4, 1
        addi    t3, t3, 1
        addi    t6, t6, 8
        li      t5, 4
        bne     t3, t5, .Lspi_transfer_c6_pack_loop
        sw      t2, 0(t0)
        addi    t0, t0, 4
        mv      t2, zero
        mv      t3, zero
        mv      t6, zero
        j       .Lspi_transfer_c6_pack_loop
.Lspi_transfer_c6_pack_finish:
        beqz    t3, .Lspi_transfer_c6_pack_done
        sw      t2, 0(t0)
.Lspi_transfer_c6_pack_done:
        li      t0, C6_SPI2_MS_DLEN
        slli    t2, t1, 3
        addi    t2, t2, -1
        sw      t2, 0(t0)

        li      t0, C6_SPI2_USER
        li      t2, C6_SPI_USER_MOSI_VALUE
        beqz    a5, .Lspi_transfer_c6_user_store
        li      t3, C6_SPI_USR_MISO
        or      t2, t2, t3
.Lspi_transfer_c6_user_store:
        sw      t2, 0(t0)

        li      t0, C6_SPI2_DMA_INT_CLR
        li      t2, C6_SPI_TRANS_DONE
        sw      t2, 0(t0)

        li      t0, C6_SPI2_CMD
        li      t2, C6_SPI_UPDATE
        sw      t2, 0(t0)
        mv      t3, a7
.Lspi_transfer_c6_wait_update:
        lw      t4, 0(t0)
        and     t4, t4, t2
        beqz    t4, .Lspi_transfer_c6_start
        beqz    t3, .Lspi_transfer_timeout
        addi    t3, t3, -1
        j       .Lspi_transfer_c6_wait_update

.Lspi_transfer_c6_start:
        li      t2, C6_SPI_USR
        sw      t2, 0(t0)

        li      t0, C6_SPI2_DMA_INT_RAW
        li      t2, C6_SPI_TRANS_DONE
        mv      t3, a7
.Lspi_transfer_c6_wait_done:
        lw      t4, 0(t0)
        and     t4, t4, t2
        bnez    t4, .Lspi_transfer_c6_read
        beqz    t3, .Lspi_transfer_timeout
        addi    t3, t3, -1
        j       .Lspi_transfer_c6_wait_done

.Lspi_transfer_c6_read:
        beqz    a5, .Lspi_transfer_c6_advance
        li      t0, C6_SPI2_W0
        mv      t4, zero                /* bytes copied */
        li      t3, 4                   /* force initial word load */
.Lspi_transfer_c6_read_loop:
        beq     t4, t1, .Lspi_transfer_c6_advance
        li      t5, 4
        bne     t3, t5, .Lspi_transfer_c6_have_word
        lw      t2, 0(t0)
        addi    t0, t0, 4
        mv      t3, zero
.Lspi_transfer_c6_have_word:
        andi    t5, t2, 0xff
        sb      t5, 0(a5)
        addi    a5, a5, 1
        srli    t2, t2, 8
        addi    t3, t3, 1
        addi    t4, t4, 1
        j       .Lspi_transfer_c6_read_loop

.Lspi_transfer_c6_advance:
        sub     a6, a6, t1
        bnez    a6, .Lspi_transfer_c6_chunk
        j       .Lspi_transfer_success_counted
        .endif

        .ifdef TARGET_QEMU_VIRT
        la      t2, spi_model_tx_log
        la      t3, spi_model_rx_source
        mv      t4, a0                  /* current tx pointer, or 0 */
        mv      t5, a1                  /* current rx pointer, or 0 */
        mv      t6, zero                /* byte index */
.Lspi_transfer_qemu_loop:
        beq     t6, a2, .Lspi_transfer_success_counted
        beqz    t4, .Lspi_transfer_qemu_zero_tx
        lbu     t1, 0(t4)
        addi    t4, t4, 1
        j       .Lspi_transfer_qemu_store_tx
.Lspi_transfer_qemu_zero_tx:
        mv      t1, zero
.Lspi_transfer_qemu_store_tx:
        sb      t1, 0(t2)
        addi    t2, t2, 1
        beqz    t5, .Lspi_transfer_qemu_next
        lbu     t1, 0(t3)
        sb      t1, 0(t5)
        addi    t5, t5, 1
.Lspi_transfer_qemu_next:
        addi    t3, t3, 1
        addi    t6, t6, 1
        j       .Lspi_transfer_qemu_loop
        .endif

.Lspi_transfer_zero:
        la      t0, spi_model_last_status
        sw      zero, 0(t0)
        la      t0, spi_model_tx_log_len
        sw      zero, 0(t0)
        li      a0, SPI_OK
        ret

.Lspi_transfer_success_counted:
        la      t0, spi_model_last_status
        sw      zero, 0(t0)
        la      t0, spi_model_tx_log_len
        sw      a2, 0(t0)
        la      t0, spi_model_transfer_count
        lw      t1, 0(t0)
        addi    t1, t1, 1
        sw      t1, 0(t0)
        li      a0, SPI_OK
        ret

.Lspi_transfer_invalid:
        li      a0, SPI_ERR_INVAL
        j       .Lspi_transfer_status_return
.Lspi_transfer_overflow:
        li      a0, SPI_ERR_OVERFLOW
        j       .Lspi_transfer_status_return
.Lspi_transfer_timeout:
        li      a0, SPI_ERR_TIMEOUT
.Lspi_transfer_status_return:
        la      t0, spi_model_last_status
        sw      a0, 0(t0)
        ret

        .size   spi_transfer, . - spi_transfer
