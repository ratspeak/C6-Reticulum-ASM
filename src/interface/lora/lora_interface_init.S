# ============================================================================
# @function:    lora_interface_init
# @module:      interface/lora
# @inputs:      a0 = timeout polls, or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       16
# @cycles:      bounded (sx1262_init)
# @ct:          not-required
# @spec:        milestone-8 reticulum-interface-glue
# @verify:      proofs/lora/lora_interface_init_contract.py, proofs/lora/lora_interface_state.tla
# @tests:       tests/interface/test_lora_interface_init.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.lora_interface_init, "ax", @progbits
        .global lora_interface_init
        .type   lora_interface_init, @function
lora_interface_init:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s0, 8(sp)

        mv      s0, a0
        la      t0, lora_interface_initialized
        sw      zero, 0(t0)
        la      t0, lora_interface_last_status
        sw      zero, 0(t0)

        mv      a0, s0
        call    sx1262_init

        la      t0, lora_interface_last_status
        sw      a0, 0(t0)
        bnez    a0, .Llora_interface_init_return

        la      t0, lora_interface_initialized
        li      t1, 1
        sw      t1, 0(t0)

.Llora_interface_init_return:
        lw      s0, 8(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   lora_interface_init, . - lora_interface_init
