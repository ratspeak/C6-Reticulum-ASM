# ============================================================================
# @function:    gpio_read
# @module:      interface/gpio
# @inputs:      a0 = GPIO number
# @outputs:     a0 = level (0 or 1), or GPIO_ERR_INVAL on unsupported/unconfigured pin
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       0
# @cycles:      bounded (~26 instructions)
# @ct:          not-required
# @spec:        milestone-8 gpio helpers
# @verify:      proofs/gpio/gpio_contract.py
# @tests:       tests/interface/test_gpio_helpers.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "gpio.S"

        .section .text.gpio_read, "ax", @progbits
        .global gpio_read
        .type   gpio_read, @function
gpio_read:
        li      t0, GPIO_PIN_LIMIT
        bgeu    a0, t0, .Lgpio_read_invalid
        li      t0, 1
        sll     t1, t0, a0

        li      t2, GPIO_LORA_INPUT_MASK
        and     t3, t1, t2
        beqz    t3, .Lgpio_read_invalid

        la      t2, gpio_model_configured
        lw      t3, 0(t2)
        and     t3, t3, t1
        beqz    t3, .Lgpio_read_invalid

        la      t2, gpio_model_direction
        lw      t3, 0(t2)
        and     t3, t3, t1
        bnez    t3, .Lgpio_read_invalid

        .ifdef TARGET_C6
        li      t2, C6_GPIO_IN
        lw      t3, 0(t2)
        .else
        la      t2, gpio_model_level
        lw      t3, 0(t2)
        .endif
        and     t3, t3, t1
        snez    a0, t3
        ret

.Lgpio_read_invalid:
        li      a0, GPIO_ERR_INVAL
        ret

        .size   gpio_read, . - gpio_read
