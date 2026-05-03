# ============================================================================
# @function:    identity_create
# @module:      identity
# @inputs:      a0 = identity_t* out (160 bytes)
# @outputs:     a0 = 0; out filled with Reticulum identity layout
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0
# @stack:       16
# @cycles:      bounded (~x25519_keypair + ed25519_keypair + identity_hash)
# @ct:          required
# @spec:        milestone-3 identity_create; upstream Reticulum private/public key byte order
# @verify:      proofs/identity/IdentityCreate.cry, proofs/identity/identity_create.saw
# @tests:       tests/identity/test_identity_create.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Fill identity_t in the canonical milestone-3 layout:
 *
 *   [0..63]     private_key = x25519_sk || ed25519_seed
 *   [64..127]   public_key  = x25519_pk || ed25519_pk
 *   [128..143]  identity_hash(public_key)
 *   [144..159]  reserved zero padding
 *
 * The caller is responsible for initialising the RNG state before calling
 * identity_create, matching the existing keypair primitives.
 */

        .include "identity.S"

        .equ FRAME,  16
        .equ S0_OFF, 8
        .equ RA_OFF, 12

        .section .text.identity_create, "ax", @progbits
        .global identity_create
        .type   identity_create, @function
identity_create:
        addi    sp, sp, -FRAME
        sw      s0, S0_OFF(sp)
        sw      ra, RA_OFF(sp)
        mv      s0, a0

        /* x25519_keypair(pk_out=out+64, sk_out=out+0) */
        addi    a0, s0, IDENTITY_OFF_X25519_PK
        addi    a1, s0, IDENTITY_OFF_X25519_SK
        call    x25519_keypair

        /* ed25519_keypair(sk_out=out+32, pk_out=out+96) */
        addi    a0, s0, IDENTITY_OFF_ED25519_SK
        addi    a1, s0, IDENTITY_OFF_ED25519_PK
        call    ed25519_keypair

        /* identity_hash(public_key=out+64, hash_out=out+128) */
        addi    a0, s0, IDENTITY_OFF_X25519_PK
        addi    a1, s0, IDENTITY_OFF_HASH
        call    identity_hash

        /* Reserved padding must be deterministic zeroes. */
        addi    t0, s0, IDENTITY_OFF_RESERVED
        sw      zero, 0(t0)
        sw      zero, 4(t0)
        sw      zero, 8(t0)
        sw      zero, 12(t0)

        li      a0, 0
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   identity_create, . - identity_create
