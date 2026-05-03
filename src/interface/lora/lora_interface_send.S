# ============================================================================
# @function:    lora_interface_send
# @module:      interface/lora
# @inputs:      a0 = raw Reticulum packet ptr, a1 = packet len, a2 = timeout polls or 0 for default
# @outputs:     a0 = LORA_OK or negative LORA_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       32
# @cycles:      bounded (sx1262_send_frame)
# @ct:          not-required
# @spec:        milestone-8 reticulum-interface-glue
# @verify:      proofs/lora/lora_interface_send_contract.py, proofs/lora/lora_interface_state.tla
# @tests:       tests/interface/test_lora_interface_send.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"

        .section .text.lora_interface_send, "ax", @progbits
        .global lora_interface_send
        .type   lora_interface_send, @function
lora_interface_send:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)
        sw      s2, 16(sp)

        mv      s0, a0                  /* packet ptr */
        mv      s1, a1                  /* packet len */
        mv      s2, a2                  /* timeout polls */

        la      t0, lora_interface_tx_len
        sw      zero, 0(t0)

        la      t0, lora_interface_initialized
        lw      t1, 0(t0)
        beqz    t1, .Llora_interface_send_not_initialized

        mv      a0, s0
        mv      a1, s1
        mv      a2, s2
        call    sx1262_send_frame
        la      t0, lora_interface_last_status
        sw      a0, 0(t0)
        bnez    a0, .Llora_interface_send_return

        la      t0, lora_interface_tx_len
        sw      s1, 0(t0)
        j       .Llora_interface_send_return

.Llora_interface_send_not_initialized:
        li      a0, LORA_ERR_NOT_INITIALIZED
        la      t0, lora_interface_last_status
        sw      a0, 0(t0)

.Llora_interface_send_return:
        lw      s2, 16(sp)
        lw      s1, 20(sp)
        lw      s0, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   lora_interface_send, . - lora_interface_send
