# ============================================================================
# @function:    destination_name_hash
# @module:      destination
# @inputs:      a0 = destination-name bytes ptr, a1 = destination-name length, a2 = name_hash_out ptr (10 bytes)
# @outputs:     name_hash_out = SHA256(name_bytes)[0:10]
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s2 (saved+restored)
# @stack:       16
# @cycles:      bounded (one SHA-256 over name length plus 10-byte copy; length is public)
# @ct:          not-required
# @spec:        upstream Reticulum RNS/Destination.py Destination.hash name_hash derivation; milestone-3 destination hashes
# @verify:      proofs/destination/DestinationHash.cry, proofs/destination/destination_name_hash.saw
# @tests:       tests/destination/test_destination_name_hash.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Compute the Reticulum destination name hash:
 *
 *     SHA256(destination_name_bytes)[0:10]
 *
 * The caller supplies the already-expanded name without any identity
 * suffix, matching Destination.expand_name(None, app_name, *aspects).
 * The SHA-256 singleton ctx/digest buffers are used sequentially.
 */

        .include "destination.S"
        .include "sha256.S"

        .section .text.destination_name_hash, "ax", @progbits
        .global destination_name_hash
        .type   destination_name_hash, @function
destination_name_hash:
        addi    sp, sp, -16
        sw      ra, 12(sp)
        sw      s2, 8(sp)
        sw      s1, 4(sp)
        sw      s0, 0(sp)

        mv      s0, a0                  /* name ptr                    */
        mv      s1, a1                  /* name len                    */
        mv      s2, a2                  /* output ptr                  */

        la      a0, sha256_ctx
        call    sha256_init
        la      a0, sha256_ctx
        mv      a1, s0
        mv      a2, s1
        call    sha256_update
        la      a0, sha256_ctx
        la      a1, sha256_digest_buf
        call    sha256_final

        la      t0, sha256_digest_buf
        mv      t1, s2
        li      t2, DESTINATION_NAME_HASH_SIZE
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

        .size   destination_name_hash, . - destination_name_hash
