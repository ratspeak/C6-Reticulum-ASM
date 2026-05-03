# ============================================================================
# @function:    gpio_write
# @module:      interface/gpio
# @inputs:      a0 = GPIO number, a1 = level (0 or 1)
# @outputs:     a0 = GPIO_OK, or GPIO_ERR_INVAL on unsupported/unconfigured pin
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       0
# @cycles:      bounded (~34 instructions)
# @ct:          not-required
# @spec:        milestone-8 gpio helpers
# @verify:      proofs/gpio/gpio_contract.py
# @tests:       tests/interface/test_gpio_helpers.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "gpio.S"

        .section .text.gpio_write, "ax", @progbits
        .global gpio_write
        .type   gpio_write, @function
gpio_write:
        li      t0, GPIO_PIN_LIMIT
        bgeu    a0, t0, .Lgpio_write_invalid
        li      t0, 1
        bgtu    a1, t0, .Lgpio_write_invalid
        sll     t1, t0, a0

        li      t2, GPIO_LORA_OUTPUT_MASK
        and     t3, t1, t2
        beqz    t3, .Lgpio_write_invalid

        la      t2, gpio_model_configured
        lw      t3, 0(t2)
        and     t3, t3, t1
        beqz    t3, .Lgpio_write_invalid

        la      t2, gpio_model_direction
        lw      t3, 0(t2)
        and     t3, t3, t1
        beqz    t3, .Lgpio_write_invalid

        .ifdef TARGET_C6
        beqz    a1, .Lgpio_write_c6_low
        li      t2, C6_GPIO_OUT_W1TS
        sw      t1, 0(t2)
        j       .Lgpio_write_model
.Lgpio_write_c6_low:
        li      t2, C6_GPIO_OUT_W1TC
        sw      t1, 0(t2)
        .endif

.Lgpio_write_model:
        la      t2, gpio_model_level
        lw      t3, 0(t2)
        beqz    a1, .Lgpio_write_model_low
        or      t3, t3, t1
        j       .Lgpio_write_model_store
.Lgpio_write_model_low:
        not     t4, t1
        and     t3, t3, t4
.Lgpio_write_model_store:
        sw      t3, 0(t2)
        li      a0, GPIO_OK
        ret

.Lgpio_write_invalid:
        li      a0, GPIO_ERR_INVAL
        ret

        .size   gpio_write, . - gpio_write
