# ============================================================================
# @function:    sha256_compress
# @module:      crypto/sha256
# @inputs:      a0 = ctx_ptr (sha256_ctx*; H[0..7] read+written), a1 = block_ptr (64 bytes, BE per FIPS 180-4)
# @outputs:     ctx->H[0..7] updated per FIPS 180-4 §6.2.2; block contents unchanged
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11 (saved+restored)
# @stack:       304
# @cycles:      bounded (~64 round bodies × ~30 instructions + 64-word schedule + I/O ≈ 2700 instructions)
# @ct:          required
# @spec:        FIPS 180-4 §6.2.2 (SHA-256 hash computation)
# @verify:      proofs/crypto/sha256/SHA256Compress.cry, proofs/crypto/sha256/sha256_compress.saw, proofs/crypto/sha256/sha256_compress.py
# @tests:       tests/crypto/sha256/test_sha256_compress.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* SHA-256 compression function — FIPS 180-4 §6.2.2.
 *
 * Input: caller-provided ctx (H[0..7] holds intermediate hash state)
 * and a 64-byte message block in big-endian byte order.
 *
 * Algorithm:
 *   1. Build message schedule W[0..63]:
 *        W[t] = M[t]                   for t in 0..15  (BE 32-bit load)
 *        W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
 *                                       for t in 16..63
 *   2. Initialise working vars: a..h = H[0..7]
 *   3. For t in 0..63:
 *        T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
 *        T2 = Sigma0(a) + Maj(a,b,c)
 *        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2
 *   4. H[i] += {a,b,c,d,e,f,g,h}[i]
 *
 * Where (32-bit operations, ROTR = right rotate):
 *   Ch(x,y,z)   = (x & y) ^ (~x & z)
 *   Maj(x,y,z)  = (x & y) ^ (x & z) ^ (y & z)
 *   Sigma0(x)   = ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22)
 *   Sigma1(x)   = ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25)
 *   sigma0(x)   = ROTR(x,7)  ^ ROTR(x,18) ^ SHR(x,3)
 *   sigma1(x)   = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
 *
 * Constant-time by construction: every operation depends only on (H, M),
 * which are non-secret to the algorithm. No data-dependent branches.
 *
 * Stack frame (304 bytes, 16-byte aligned):
 *    0..255   W[0..63]                — 256-byte message schedule
 *  256..291   s0..s8                   — 9 × 4 callee-saved
 *      292   pad
 *      296   pad
 *      300   ra
 *
 * Register allocation across the round loop:
 *   s0..s7 = a..h (working hash vars)
 *   s8     = round counter t (0..63)
 *   t0     = W_ptr base + offset (W[t] address)
 *   t1     = K_ptr base + offset (K[t] address)
 *   t2..t6 = scratch (sigmas, Ch, Maj, T1, T2)
 *   a0     = ctx_ptr (preserved through the round loop)
 *
 * Round indexing trick: W and K are 256 bytes (64 words). At round t we
 * need W[t] = sp[t*4] and K[t] = K_base[t*4]. We keep `t*4` in a separate
 * register and step it by 4 each iteration.
 */

        .include "sha256.S"

        .section .rodata.sha256_k, "a"
        .global sha256_k
        .balign 4
sha256_k:
        .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
        .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
        .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
        .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
        .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
        .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
        .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
        .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
        .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
        .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
        .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
        .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
        .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
        .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
        .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
        .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

        .section .text.sha256_compress, "ax", @progbits
        .global sha256_compress
        .type   sha256_compress, @function
sha256_compress:
        addi    sp, sp, -304
        sw      s0, 256(sp)
        sw      s1, 260(sp)
        sw      s2, 264(sp)
        sw      s3, 268(sp)
        sw      s4, 272(sp)
        sw      s5, 276(sp)
        sw      s6, 280(sp)
        sw      s7, 284(sp)
        sw      s8, 288(sp)
        sw      ra, 300(sp)

        /* ---- 1. W[0..15]: big-endian load from block_ptr (a1) ----
         * We use byte loads so the block_ptr need not be 4-aligned. */
        mv      t0, sp                  /* W base                      */
        mv      t1, a1                  /* read pointer in M           */
        li      t6, 16                  /* counter                     */
.Lload_w:
        lbu     t2, 0(t1)
        lbu     t3, 1(t1)
        lbu     t4, 2(t1)
        lbu     t5, 3(t1)
        slli    t2, t2, 24
        slli    t3, t3, 16
        slli    t4, t4, 8
        or      t2, t2, t3
        or      t2, t2, t4
        or      t2, t2, t5
        sw      t2, 0(t0)
        addi    t0, t0, 4
        addi    t1, t1, 4
        addi    t6, t6, -1
        bnez    t6, .Lload_w

        /* ---- 2. W[16..63] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16] ----
         * Loop var: t0 = &W[t] starting at W[16]. t6 = remaining iters (48). */
        mv      t0, sp
        addi    t0, t0, 64              /* &W[16]                      */
        li      t6, 48
.Lschedule:
        lw      t1, -8(t0)              /* W[t-2]                      */
        /* sigma1(t1) = ROTR(t1,17) ^ ROTR(t1,19) ^ SHR(t1,10)         */
        srli    t2, t1, 17
        slli    t3, t1, 15
        or      t2, t2, t3              /* ROTR(t1,17)                 */
        srli    t3, t1, 19
        slli    t4, t1, 13
        or      t3, t3, t4              /* ROTR(t1,19)                 */
        srli    t4, t1, 10              /* SHR(t1,10)                  */
        xor     t2, t2, t3
        xor     t2, t2, t4              /* sigma1                      */

        lw      t3, -28(t0)             /* W[t-7]                      */
        add     t2, t2, t3

        lw      t1, -60(t0)             /* W[t-15]                     */
        /* sigma0(t1) = ROTR(t1,7) ^ ROTR(t1,18) ^ SHR(t1,3)           */
        srli    t3, t1, 7
        slli    t4, t1, 25
        or      t3, t3, t4              /* ROTR(t1,7)                  */
        srli    t4, t1, 18
        slli    t5, t1, 14
        or      t4, t4, t5              /* ROTR(t1,18)                 */
        srli    t5, t1, 3               /* SHR(t1,3)                   */
        xor     t3, t3, t4
        xor     t3, t3, t5              /* sigma0                      */
        add     t2, t2, t3

        lw      t3, -64(t0)             /* W[t-16]                     */
        add     t2, t2, t3

        sw      t2, 0(t0)
        addi    t0, t0, 4
        addi    t6, t6, -1
        bnez    t6, .Lschedule

        /* ---- 3. Initialise working vars from H ----
         * s0..s7 = a..h. */
        lw      s0, 0(a0)               /* a = H[0]                    */
        lw      s1, 4(a0)
        lw      s2, 8(a0)
        lw      s3, 12(a0)
        lw      s4, 16(a0)
        lw      s5, 20(a0)
        lw      s6, 24(a0)
        lw      s7, 28(a0)              /* h = H[7]                    */

        /* ---- 4. 64-round main loop ----
         * s8 = byte offset (t * 4); ranges 0..252.
         * a3 = K base; a4 = W base. */
        li      s8, 0
        la      a3, sha256_k
        mv      a4, sp
.Lround:
        /* T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
         * Sigma1(x) = ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) */
        srli    t0, s4, 6
        slli    t1, s4, 26
        or      t0, t0, t1              /* ROTR(e,6)                   */
        srli    t1, s4, 11
        slli    t2, s4, 21
        or      t1, t1, t2              /* ROTR(e,11)                  */
        srli    t2, s4, 25
        slli    t3, s4, 7
        or      t2, t2, t3              /* ROTR(e,25)                  */
        xor     t0, t0, t1
        xor     t0, t0, t2              /* Sigma1(e)                   */

        /* Ch(e,f,g) = (e & f) ^ (~e & g) */
        and     t1, s4, s5              /* e & f                       */
        not     t2, s4
        and     t2, t2, s6              /* ~e & g                      */
        xor     t1, t1, t2              /* Ch(e,f,g)                   */

        add     t0, t0, t1              /* Sigma1 + Ch                 */
        add     t0, t0, s7              /* + h                         */

        add     t1, a3, s8              /* &K[t]                       */
        lw      t1, 0(t1)
        add     t0, t0, t1              /* + K[t]                      */
        add     t1, a4, s8              /* &W[t]                       */
        lw      t1, 0(t1)
        add     t0, t0, t1              /* T1 in t0                    */

        /* T2 = Sigma0(a) + Maj(a,b,c)
         * Sigma0(x) = ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) */
        srli    t1, s0, 2
        slli    t2, s0, 30
        or      t1, t1, t2              /* ROTR(a,2)                   */
        srli    t2, s0, 13
        slli    t3, s0, 19
        or      t2, t2, t3              /* ROTR(a,13)                  */
        srli    t3, s0, 22
        slli    t4, s0, 10
        or      t3, t3, t4              /* ROTR(a,22)                  */
        xor     t1, t1, t2
        xor     t1, t1, t3              /* Sigma0(a)                   */

        /* Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c) */
        and     t2, s0, s1              /* a & b                       */
        and     t3, s0, s2              /* a & c                       */
        and     t4, s1, s2              /* b & c                       */
        xor     t2, t2, t3
        xor     t2, t2, t4              /* Maj                         */
        add     t1, t1, t2              /* T2 in t1                    */

        /* h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2 */
        mv      s7, s6                  /* h = g                       */
        mv      s6, s5                  /* g = f                       */
        mv      s5, s4                  /* f = e                       */
        add     s4, s3, t0              /* e = d + T1                  */
        mv      s3, s2                  /* d = c                       */
        mv      s2, s1                  /* c = b                       */
        mv      s1, s0                  /* b = a                       */
        add     s0, t0, t1              /* a = T1 + T2                 */

        addi    s8, s8, 4
        li      t0, 256                 /* 64 rounds * 4 bytes         */
        bne     s8, t0, .Lround

        /* ---- 5. H[i] += working var i ---- */
        lw      t0, 0(a0); add t0, t0, s0; sw t0, 0(a0)
        lw      t0, 4(a0); add t0, t0, s1; sw t0, 4(a0)
        lw      t0, 8(a0); add t0, t0, s2; sw t0, 8(a0)
        lw      t0, 12(a0); add t0, t0, s3; sw t0, 12(a0)
        lw      t0, 16(a0); add t0, t0, s4; sw t0, 16(a0)
        lw      t0, 20(a0); add t0, t0, s5; sw t0, 20(a0)
        lw      t0, 24(a0); add t0, t0, s6; sw t0, 24(a0)
        lw      t0, 28(a0); add t0, t0, s7; sw t0, 28(a0)

        lw      s0, 256(sp)
        lw      s1, 260(sp)
        lw      s2, 264(sp)
        lw      s3, 268(sp)
        lw      s4, 272(sp)
        lw      s5, 276(sp)
        lw      s6, 280(sp)
        lw      s7, 284(sp)
        lw      s8, 288(sp)
        lw      ra, 300(sp)
        addi    sp, sp, 304
        ret

        .size   sha256_compress, . - sha256_compress
