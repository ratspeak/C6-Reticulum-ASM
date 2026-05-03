# ============================================================================
# @function:    ed25519_keypair
# @module:      crypto/ed25519
# @inputs:      a0 = sk_out ptr (32 bytes; filled with random seed)
#               a1 = pk_out ptr (32 bytes; derived public key)
# @outputs:     sk_out = 32 random bytes (the seed; this IS the
#                        private key — RFC 8032 §5.1.5).
#               pk_out = 32-byte encoded point A = a · B, where
#                        a is the clamped lower half of SHA-512(seed).
# @clobbers:    t0..t6, a2..a7, s0, s1
# @preserves:   sp, gp, ra, all other callee-saved
# @stack:       192
# @cycles:      bounded (≈ rng + sha512 + scalarmult + compress ≈ 9M)
# @ct:          required (rng_bytes is fake-CT for QEMU; production
#               TRNG-seeded HMAC-DRBG is also CT. SHA-512, clamp,
#               scalarmult, compress are all CT.)
# @spec:        RFC 8032 §5.1.5 — Ed25519 key generation.
#                 1. seed := 32 random bytes        (sk_out)
#                 2. h := SHA-512(seed) (64 bytes)
#                 3. clamp the lower 32 bytes of h:
#                      h[0]  &= 248, h[31] &= 127, h[31] |= 64
#                 4. A := scalarmult(h_lower, B)    (point)
#                 5. pk := compress(A)              (pk_out)
# @verify:      kat-only; ed25519_keypair is end-to-end glue over
#               rng_bytes + sha512_* + ed25519_scalarmult +
#               ed25519_point_compress. Each underlying primitive now
#               carries Tier A Cryptol+SAW (proofs/crypto/sha512/,
#               proofs/crypto/ed25519/) plus per-function Tier C
#               QEMU/pyca KATs; the keypair-level QEMU pytest with
#               the deterministic-fake RNG compares (sk, pk) against
#               pyca/cryptography's Ed25519PrivateKey.from_private_bytes
#               for the seed the fake RNG produces. A dedicated
#               keypair-level Tier A would have to symbolically run
#               sha512_compress + 256 point doublings + field_inv,
#               which is dominated by the underlying tier-A coverage.
# @tests:       tests/crypto/ed25519/test_ed25519_keypair.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* Stack frame (192 bytes, 16-byte aligned):
 *      0..159   point_buf   (160 bytes; A = a·B in extended coords)
 *    160..175   pad
 *    176..183   s0, s1
 *    184..187   ra
 *    188..191   pad
 */

        .include "ed25519.S"
        .include "sha512.S"

        .equ POINT_OFF, 0
        .equ S0_OFF,  176
        .equ S1_OFF,  180
        .equ RA_OFF,  184
        .equ FRAME,   192

        .section .text.ed25519_keypair, "ax", @progbits
        .global ed25519_keypair
        .type   ed25519_keypair, @function
ed25519_keypair:
        addi    sp, sp, -FRAME
        sw      ra, RA_OFF(sp)
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        mv      s0, a0                          /* sk_out                 */
        mv      s1, a1                          /* pk_out                 */

        # 1. Fill sk_out with 32 random bytes (the seed).
        mv      a0, s0
        li      a1, 32
        call    rng_bytes

        # 2. SHA-512(seed) → sha512_digest_buf
        la      a0, sha512_ctx
        call    sha512_init
        la      a0, sha512_ctx
        mv      a1, s0
        li      a2, 32
        call    sha512_update
        la      a0, sha512_ctx
        la      a1, sha512_digest_buf
        call    sha512_final

        # 3. Clamp lower 32 bytes of the digest:
        #    digest[0]  &= 248
        #    digest[31] &= 127
        #    digest[31] |= 64
        la      t0, sha512_digest_buf
        lbu     t1, 0(t0)
        andi    t1, t1, 248
        sb      t1, 0(t0)
        lbu     t1, 31(t0)
        andi    t1, t1, 127
        ori     t1, t1, 64
        sb      t1, 31(t0)

        # 4. point_buf := scalarmult(clamped_scalar, base_point)
        addi    a0, sp, POINT_OFF
        la      a1, sha512_digest_buf
        la      a2, ed25519_base_point
        call    ed25519_scalarmult

        # 5. pk_out := compress(point_buf)
        mv      a0, s1
        addi    a1, sp, POINT_OFF
        call    ed25519_point_compress

        lw      s1, S1_OFF(sp)
        lw      s0, S0_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   ed25519_keypair, . - ed25519_keypair
