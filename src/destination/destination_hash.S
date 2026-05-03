# ============================================================================
# @function:    destination_hash
# @module:      destination
# @inputs:      a0 = name_hash ptr (10 bytes), a1 = identity_hash ptr (16 bytes), a2 = destination_hash_out ptr (16 bytes)
# @outputs:     destination_hash_out = SHA256(name_hash || identity_hash)[0:16]
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s2 (saved+restored)
# @stack:       16
# @cycles:      bounded (one SHA-256 over 26 fixed input bytes plus 16-byte copy)
# @ct:          not-required
# @spec:        upstream Reticulum RNS/Destination.py Destination.hash address hash derivation; milestone-3 destination hashes
# @verify:      proofs/destination/DestinationHash.cry, proofs/destination/destination_hash.saw
# @tests:       tests/destination/test_destination_hash.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Compute the Reticulum addressable destination hash:
 *
 *     SHA256(name_hash[10] || identity_hash[16])[0:16]
 *
 * The two fixed-size inputs are streamed into SHA-256 without assembling a
 * temporary concatenation buffer.
 */

        .include "destination.S"
        .include "sha256.S"

        .section .text.destination_hash, "ax", @progbits
        .global destination_hash
        .type   destination_hash, @function
destination_hash:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* name_hash ptr               */
        mv      s1, a1                  /* identity_hash ptr           */
        mv      s2, a2                  /* output ptr                  */

        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        mv      a1, s0
        li      a2, DESTINATION_NAME_HASH_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        mv      a1, s1
        li      a2, DESTINATION_IDENTITY_HASH_SIZE
        call    sha256_update
        la      a0, sha256_ctx
        la      a1, sha256_digest_buf
        call    sha256_final

        la      t0, sha256_digest_buf
        mv      t1, s2
        li      t2, DESTINATION_HASH_SIZE
1:      beqz    t2, 2f
        lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        j       1b

2:      lw      s0, 0(sp)
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      ra, 12(sp)
        addi    sp, sp, 16
        ret

        .size   destination_hash, . - destination_hash
