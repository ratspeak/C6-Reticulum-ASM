# ============================================================================
# @function:    lora_interface_poll
# @module:      interface/lora
# @inputs:      a0 = timeout polls or 0 for default
# @outputs:     a0 = dispatch status, positive/zero stack status, or negative LORA_ERR_*/LINK_ERR_*
# @clobbers:    a0..a5, t0..t6
# @preserves:   sp, gp, ra, s0..s11
# @stack:       32
# @cycles:      bounded (one SX1262 RX poll plus packet dispatch)
# @ct:          not-required
# @spec:        milestone-8 reticulum-interface-glue
# @verify:      proofs/lora/lora_interface_poll_contract.py, proofs/lora/lora_interface_state.tla
# @tests:       tests/interface/test_lora_interface_poll.py
# @adrs:        0001, 0002, 0003, 0005, 0006, 0009, 0011
# @status:      verified
# ============================================================================

        .include "lora.S"
        .include "transport.S"

        .section .text.lora_interface_poll, "ax", @progbits
        .global lora_interface_poll
        .type   lora_interface_poll, @function
lora_interface_poll:
        addi    sp, sp, -32
        sw      ra, 28(sp)
        sw      s0, 24(sp)
        sw      s1, 20(sp)

        mv      s0, a0                  /* timeout polls */
        la      t0, lora_interface_rx_len
        sw      zero, 0(t0)
        la      t0, lora_interface_dispatch_status
        sw      zero, 0(t0)

        la      t0, lora_interface_initialized
        lw      t1, 0(t0)
        beqz    t1, .Llora_interface_poll_not_initialized

        la      a0, lora_interface_rx_buf
        li      a1, SX1262_BENCH_PAYLOAD_MAX
        mv      a2, s0
        call    sx1262_poll_receive
        blez    a0, .Llora_interface_poll_store_status

        mv      s1, a0                  /* received length */
        la      t0, lora_interface_rx_len
        sw      s1, 0(t0)

        la      a0, lora_interface_rx_buf
        mv      a1, s1
        li      a2, TRANSPORT_INTERFACE_LORA
        call    link_process_packet
        la      t0, lora_interface_dispatch_status
        sw      a0, 0(t0)
        j       .Llora_interface_poll_store_status

.Llora_interface_poll_not_initialized:
        li      a0, LORA_ERR_NOT_INITIALIZED

.Llora_interface_poll_store_status:
        la      t0, lora_interface_last_status
        sw      a0, 0(t0)

        lw      s1, 20(sp)
        lw      s0, 24(sp)
        lw      ra, 28(sp)
        addi    sp, sp, 32
        ret

        .size   lora_interface_poll, . - lora_interface_poll
