# ============================================================================
# @function:    link_request_build
# @module:      link
# @inputs:      a0 = destination_hash ptr (16 bytes), a1 = local_x25519_public ptr (32 bytes), a2 = local_ed25519_public ptr (32 bytes), a3 = raw packet out ptr, a4 = raw packet capacity
# @outputs:     a0 = 86 on success, -1 on invalid input, -2 on overflow
# @clobbers:    a0, t0..t6
# @preserves:   sp, gp, ra, all callee-saved
# @stack:       0
# @cycles:      bounded (~260)
# @ct:          not-required
# @spec:        milestone-6 link_request_build; upstream RNS.Link current request payload subset
# @verify:      proofs/link/link_request.py
# @tests:       tests/link/test_link_request.py
# @adrs:        0001, 0002, 0005, 0006, 0009
# @status:      verified
# ============================================================================

/* Build a current Reticulum HEADER_1 link request packet:
 *
 *   0x02 || 0x00 || destination_hash || 0x00 ||
 *   x25519_public || ed25519_link_signing_public || 0x20 0x01 0xf4
 *
 * The signalling bytes are RNS.Link.signalling_bytes(500, AES-256-CBC).
 */

        .include "link.S"

        .section .text.link_request_build, "ax", @progbits
        .global link_request_build
        .type   link_request_build, @function
link_request_build:
        beqz    a0, .Llrb_invalid
        beqz    a1, .Llrb_invalid
        beqz    a2, .Llrb_invalid
        beqz    a3, .Llrb_invalid

        li      t0, LINK_REQUEST_RAW_LEN
        bltu    a4, t0, .Llrb_overflow

        li      t1, LINK_REQUEST_HEADER_FLAGS
        sb      t1, LINK_REQUEST_RAW_OFF_FLAGS(a3)
        sb      zero, LINK_REQUEST_RAW_OFF_HOPS(a3)
        sb      zero, LINK_REQUEST_RAW_OFF_CONTEXT(a3)

        mv      t2, a0
        addi    t3, a3, LINK_REQUEST_RAW_OFF_DEST_HASH
        li      t4, LINK_DESTINATION_HASH_SIZE
.Llrb_copy_dest:
        lbu     t5, 0(t2)
        sb      t5, 0(t3)
        addi    t2, t2, 1
        addi    t3, t3, 1
        addi    t4, t4, -1
        bnez    t4, .Llrb_copy_dest

        mv      t2, a1
        addi    t3, a3, LINK_REQUEST_RAW_OFF_X25519_PUB
        li      t4, LINK_X25519_PUB_SIZE
.Llrb_copy_x25519:
        lbu     t5, 0(t2)
        sb      t5, 0(t3)
        addi    t2, t2, 1
        addi    t3, t3, 1
        addi    t4, t4, -1
        bnez    t4, .Llrb_copy_x25519

        mv      t2, a2
        addi    t3, a3, LINK_REQUEST_RAW_OFF_ED25519_PUB
        li      t4, LINK_ED25519_PUB_SIZE
.Llrb_copy_ed25519:
        lbu     t5, 0(t2)
        sb      t5, 0(t3)
        addi    t2, t2, 1
        addi    t3, t3, 1
        addi    t4, t4, -1
        bnez    t4, .Llrb_copy_ed25519

        li      t1, LINK_SIGNAL_BYTE0
        sb      t1, LINK_REQUEST_RAW_OFF_SIGNAL0(a3)
        li      t1, LINK_SIGNAL_BYTE1
        sb      t1, LINK_REQUEST_RAW_OFF_SIGNAL1(a3)
        li      t1, LINK_SIGNAL_BYTE2
        sb      t1, LINK_REQUEST_RAW_OFF_SIGNAL2(a3)

        li      a0, LINK_REQUEST_RAW_LEN
        ret

.Llrb_overflow:
        li      a0, LINK_ERR_OVERFLOW
        ret

.Llrb_invalid:
        li      a0, LINK_ERR_INVAL
        ret

        .size   link_request_build, . - link_request_build
