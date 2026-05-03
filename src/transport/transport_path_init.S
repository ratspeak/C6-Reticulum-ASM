# ============================================================================
# @function:    transport_path_init
# @module:      transport
# @inputs:      (none)
# @outputs:     a0 = 0
# @clobbers:    a0, t0..t4
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~832 byte stores)
# @ct:          not-required
# @spec:        milestone-5 transport_path_init
# @verify:      proofs/transport/path_table.py
# @tests:       tests/transport/test_path_table.py
# @adrs:        0001, 0002, 0005, 0009
# @status:      verified
# ============================================================================

/* Clear the fixed-capacity RAM path table. */

        .include "transport.S"

        .section .text.transport_path_init, "ax", @progbits
        .global transport_path_init
        .type   transport_path_init, @function
transport_path_init:
        la      t0, transport_path_table
        li      t1, TRANSPORT_PATH_TABLE_SIZE
        beqz    t1, 2f
1:      sb      zero, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        bnez    t1, 1b
2:      li      a0, TRANSPORT_OK
        ret

        .size   transport_path_init, . - transport_path_init
