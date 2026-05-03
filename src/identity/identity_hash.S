# ============================================================================
# @function:    identity_hash
# @module:      identity
# @inputs:      a0 = public_key ptr (64 bytes), a1 = hash_out ptr (16 bytes)
# @outputs:     hash_out[0..15] = SHA256(public_key[0..63])[0..15]
# @clobbers:    a0, a1, a2, t0, t1, t2, t3, ra
# @preserves:   sp, gp, s0, s1
# @stack:       160
# @cycles:      bounded (~identity wrapper + sha256 of one 64-byte block)
# @ct:          required
# @spec:        milestone-3 identity_hash; upstream Reticulum Identity.truncated_hash(get_public_key())
# @verify:      proofs/identity/IdentityHash.cry, proofs/identity/identity_hash.saw
# @tests:       tests/identity/test_identity_hash.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Compute the Reticulum identity hash:
 *
 *     SHA256(x25519_public || ed25519_public)[0:16]
 *
 * The SHA-256 context and full 32-byte digest live in this function's
 * stack frame. The digest copy happens only after sha256_final, so
 * hash_out may overlap the public-key input without changing the input
 * consumed by the hash.
 *
 * Stack frame (160 bytes, 16-byte aligned):
 *      0..111   sha256_ctx
 *    112..143   full SHA-256 digest
 *        144    saved s0
 *        148    saved s1
 *        152    pad
 *        156    saved ra
 */

        .include "sha256.S"
        .include "identity.S"

        .section .text.identity_hash, "ax", @progbits
        .global identity_hash
        .type   identity_hash, @function
identity_hash:
        addi    sp, sp, -160
        sw      s0, 144(sp)
        sw      s1, 148(sp)
        sw      ra, 156(sp)

        mv      s0, a0                  /* public_key ptr               */
        mv      s1, a1                  /* hash_out ptr                 */

        /* sha256_init(ctx) */
        mv      a0, sp
        call    sha256_init

        /* sha256_update(ctx, public_key, 64) */
        mv      a0, sp
        mv      a1, s0
        li      a2, IDENTITY_PUBLIC_KEY_SIZE
        call    sha256_update

        /* sha256_final(ctx, digest_tmp) */
        mv      a0, sp
        addi    a1, sp, SHA256_CTX_SIZE
        call    sha256_final

        /* Copy digest_tmp[0..15] to hash_out. */
        addi    t0, sp, SHA256_CTX_SIZE
        mv      t1, s1
        li      t2, IDENTITY_HASH_SIZE
1:      lbu     t3, 0(t0)
        sb      t3, 0(t1)
        addi    t0, t0, 1
        addi    t1, t1, 1
        addi    t2, t2, -1
        bnez    t2, 1b

        lw      s0, 144(sp)
        lw      s1, 148(sp)
        lw      ra, 156(sp)
        addi    sp, sp, 160
        ret

        .size   identity_hash, . - identity_hash

