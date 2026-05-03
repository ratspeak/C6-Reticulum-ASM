# ============================================================================
# @function:    spi_init
# @module:      interface/spi
# @inputs:      (none)
# @outputs:     a0 = SPI_OK
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       0
# @cycles:      bounded (~90 instructions on TARGET_C6)
# @ct:          not-required
# @spec:        milestone-8 spi-transfer-path
# @verify:      proofs/spi/spi_contract.py
# @tests:       tests/interface/test_spi_helpers.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "spi.S"

        .section .text.spi_init, "ax", @progbits
        .global spi_init
        .type   spi_init, @function
spi_init:
        .ifdef TARGET_C6
        li      t0, C6_PCR_SPI2_CONF
        li      t1, 0x00000003          /* clock enable + reset assert */
        sw      t1, 0(t0)
        li      t1, C6_PCR_SPI2_CLK_EN  /* reset release, clock kept on */
        sw      t1, 0(t0)

        li      t0, C6_PCR_SPI2_CLKM_CONF
        li      t1, C6_PCR_SPI2_CLKM_EN
        sw      t1, 0(t0)

        li      t0, C6_SPI2_CLK_GATE
        li      t1, C6_SPI_CLK_GATE_ON
        sw      t1, 0(t0)

        li      t0, C6_SPI2_CLOCK
        li      t1, C6_SPI_CLOCK_1MHZ_XTAL
        sw      t1, 0(t0)

        li      t0, C6_SPI2_USER
        li      t1, C6_SPI_DOUTDIN
        sw      t1, 0(t0)

        li      t0, C6_SPI2_MISC
        li      t1, 0x0000003f          /* disable hardware CS0..CS5 */
        sw      t1, 0(t0)

        li      t0, C6_SPI2_SLAVE
        sw      zero, 0(t0)             /* master mode, SPI mode 0 */

        li      t0, C6_SPI2_DMA_CONF
        sw      zero, 0(t0)
        li      t0, C6_SPI2_DMA_INT_ENA
        sw      zero, 0(t0)
        li      t0, C6_SPI2_DMA_INT_CLR
        li      t1, C6_SPI_TRANS_DONE
        sw      t1, 0(t0)

        /* Route Feather SCK=GPIO21 and MOSI=GPIO22 through the GPIO matrix. */
        li      t0, C6_IO_MUX_GPIO0
        li      t1, C6_SPI_SCK_PIN
        slli    t2, t1, 2
        add     t0, t0, t2
        lw      t3, 0(t0)
        li      t4, C6_IO_MUX_CLEAR_MASK
        and     t3, t3, t4
        li      t4, C6_IO_MUX_GPIO_FUNC
        or      t3, t3, t4
        sw      t3, 0(t0)

        li      t0, C6_GPIO_FUNC_OUT_SEL_BASE
        add     t0, t0, t2
        li      t3, C6_FSPICLK_OUT_IDX
        sw      t3, 0(t0)

        li      t0, C6_IO_MUX_GPIO0
        li      t1, C6_SPI_MOSI_PIN
        slli    t2, t1, 2
        add     t0, t0, t2
        lw      t3, 0(t0)
        li      t4, C6_IO_MUX_CLEAR_MASK
        and     t3, t3, t4
        li      t4, C6_IO_MUX_GPIO_FUNC
        or      t3, t3, t4
        sw      t3, 0(t0)

        li      t0, C6_GPIO_FUNC_OUT_SEL_BASE
        add     t0, t0, t2
        li      t3, C6_FSPID_OUT_IDX
        sw      t3, 0(t0)

        li      t0, C6_GPIO_ENABLE_W1TS
        li      t1, C6_SPI_OUTPUT_MASK
        sw      t1, 0(t0)

        /* Route Feather MISO=GPIO23 into the FSPIQ input signal. */
        li      t0, C6_IO_MUX_GPIO0
        li      t1, C6_SPI_MISO_PIN
        slli    t2, t1, 2
        add     t0, t0, t2
        lw      t3, 0(t0)
        li      t4, C6_IO_MUX_CLEAR_MASK
        and     t3, t3, t4
        li      t4, C6_IO_MUX_GPIO_FUNC_IE
        or      t3, t3, t4
        sw      t3, 0(t0)

        li      t0, C6_GPIO_ENABLE_W1TC
        li      t1, C6_SPI_INPUT_MASK
        sw      t1, 0(t0)

        li      t0, C6_GPIO_FUNC_IN_SEL_BASE
        li      t1, C6_FSPIQ_IN_IDX
        slli    t2, t1, 2
        add     t0, t0, t2
        li      t3, C6_SPI_MISO_PIN
        li      t4, C6_GPIO_SIG_IN_FROM_MATRIX
        or      t3, t3, t4
        sw      t3, 0(t0)
        .endif

        la      t0, spi_model_initialized
        li      t1, 1
        sw      t1, 0(t0)

        la      t0, spi_model_clock_hz
        li      t1, SPI_DEFAULT_HZ
        sw      t1, 0(t0)

        la      t0, spi_model_last_status
        sw      zero, 0(t0)

        la      t0, spi_model_transfer_count
        sw      zero, 0(t0)

        la      t0, spi_model_tx_log_len
        sw      zero, 0(t0)

        la      t0, spi_model_force_timeout
        sw      zero, 0(t0)

        li      a0, SPI_OK
        ret

        .size   spi_init, . - spi_init
