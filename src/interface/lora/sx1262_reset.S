# ============================================================================
# @function:    sx1262_reset
# @module:      interface/lora
# @inputs:      a0 = BUSY poll budget, or 0 for default
# @outputs:     a0 = LORA_OK, LORA_ERR_GPIO, or LORA_ERR_BUSY_TIMEOUT
# @clobbers:    a0..a1, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       16
# @cycles:      bounded (~10000 default BUSY polls)
# @ct:          not-required
# @spec:        milestone-8 sx1262-command-driver
# @verify:      proofs/lora/sx1262_reset_contract.py
# @tests:       tests/interface/test_sx1262_reset.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.sx1262_reset, "ax", @progbits
        .global sx1262_reset
        .type   sx1262_reset, @function
sx1262_reset:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)

        mv      s0, a0
        bnez    s0, .Lsx1262_reset_have_budget
        li      s0, SX1262_BUSY_TIMEOUT_DEFAULT
.Lsx1262_reset_have_budget:
        li      a0, GPIO_LORA_NRST_PIN
        call    gpio_config_output
        bnez    a0, .Lsx1262_reset_gpio_error

        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_config_input
        bnez    a0, .Lsx1262_reset_gpio_error

        li      a0, GPIO_LORA_NRST_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_reset_gpio_error

        li      a0, GPIO_LORA_NRST_PIN
        li      a1, 0
        call    gpio_write
        bnez    a0, .Lsx1262_reset_gpio_error

        li      a0, SX1262_RESET_LOW_US
        call    clock_delay_us

        li      a0, GPIO_LORA_NRST_PIN
        li      a1, 1
        call    gpio_write
        bnez    a0, .Lsx1262_reset_gpio_error

        li      a0, SX1262_RESET_SETTLE_US
        call    clock_delay_us

.Lsx1262_reset_busy_loop:
        li      a0, GPIO_LORA_BUSY_PIN
        call    gpio_read
        bltz    a0, .Lsx1262_reset_gpio_error
        beqz    a0, .Lsx1262_reset_ok
        beqz    s0, .Lsx1262_reset_busy_timeout
        addi    s0, s0, -1
        li      a0, SX1262_BUSY_POLL_DELAY_US
        call    clock_delay_us
        j       .Lsx1262_reset_busy_loop

.Lsx1262_reset_ok:
        li      a0, LORA_OK
        j       .Lsx1262_reset_return

.Lsx1262_reset_gpio_error:
        li      a0, LORA_ERR_GPIO
        j       .Lsx1262_reset_return

.Lsx1262_reset_busy_timeout:
        li      a0, LORA_ERR_BUSY_TIMEOUT

.Lsx1262_reset_return:
        lw      s0, 8(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   sx1262_reset, . - sx1262_reset
