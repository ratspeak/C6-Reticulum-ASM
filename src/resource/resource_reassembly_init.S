# ============================================================================
# @function:    resource_reassembly_init
# @module:      resource
# @inputs:      (none)
# @outputs:     a0 = 0
# @clobbers:    a0, t0, t1
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~632 byte stores)
# @ct:          not-required
# @spec:        milestone-7 resource_reassembly_init
# @verify:      proofs/resource/resource_reassembly_init.py
# @tests:       tests/resource/test_resource_reassembly_init.py
# @adrs:        0001, 0002, 0005, 0009
# @status:      verified
# ============================================================================

/* Clear the fixed-capacity RAM resource reassembly table. */

        .include "resource.S"

        .section .text.resource_reassembly_init, "ax", @progbits
        .global resource_reassembly_init
        .type   resource_reassembly_init, @function
resource_reassembly_init:
        la      t0, resource_reassembly_table
        li      t1, RESOURCE_REASM_TABLE_SIZE
        beqz    t1, .Lrri_done
.Lrri_clear:
        sb      zero, 0(t0)
        addi    t0, t0, 1
        addi    t1, t1, -1
        bnez    t1, .Lrri_clear
.Lrri_done:
        li      a0, RESOURCE_OK
        ret

        .size   resource_reassembly_init, . - resource_reassembly_init
