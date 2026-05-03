# ============================================================================
# @function:    gpio_config_output
# @module:      interface/gpio
# @inputs:      a0 = GPIO number
# @outputs:     a0 = GPIO_OK, or GPIO_ERR_INVAL on unsupported pin
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       0
# @cycles:      bounded (~32 instructions)
# @ct:          not-required
# @spec:        milestone-8 gpio helpers
# @verify:      proofs/gpio/gpio_contract.py
# @tests:       tests/interface/test_gpio_helpers.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "gpio.S"

        .section .text.gpio_config_output, "ax", @progbits
        .global gpio_config_output
        .type   gpio_config_output, @function
gpio_config_output:
        li      t0, GPIO_PIN_LIMIT
        bgeu    a0, t0, .Lgpio_cfg_out_invalid
        li      t1, 1
        sll     t1, t1, a0
        li      t2, GPIO_LORA_OUTPUT_MASK
        and     t3, t1, t2
        beqz    t3, .Lgpio_cfg_out_invalid
        mv      t6, a0

        .ifdef TARGET_C6
        li      t0, C6_IO_MUX_GPIO0
        slli    t2, t6, 2
        add     t0, t0, t2
        lw      t3, 0(t0)
        li      t4, C6_IO_MUX_CLEAR_MASK
        and     t3, t3, t4
        li      t4, C6_IO_MUX_GPIO_FUNC
        or      t3, t3, t4
        sw      t3, 0(t0)

        li      t0, C6_GPIO_FUNC_OUT_SEL_BASE
        add     t0, t0, t2
        li      t3, C6_SIG_GPIO_OUT_IDX
        sw      t3, 0(t0)

        li      t0, C6_GPIO_ENABLE_W1TS
        sw      t1, 0(t0)
        .endif

        la      t0, gpio_model_configured
        lw      t2, 0(t0)
        or      t2, t2, t1
        sw      t2, 0(t0)

        la      t0, gpio_model_direction
        lw      t2, 0(t0)
        or      t2, t2, t1
        sw      t2, 0(t0)

        li      a0, GPIO_OK
        ret

.Lgpio_cfg_out_invalid:
        li      a0, GPIO_ERR_INVAL
        ret

        .size   gpio_config_output, . - gpio_config_output
