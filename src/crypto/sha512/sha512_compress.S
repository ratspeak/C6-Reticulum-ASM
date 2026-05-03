# ============================================================================
# @function:    sha512_compress
# @module:      crypto/sha512
# @inputs:      a0 = ctx_ptr (sha512_ctx*; H[0..7] read+written)
#               a1 = block_ptr (128 bytes, BE per FIPS 180-4)
# @outputs:     ctx->H[0..7] updated per FIPS 180-4 §6.4.2; block contents unchanged
# @clobbers:    a0..a7, t0..t6, ra
# @preserves:   sp, gp, s0..s11 (saved+restored)
# @stack:       768
# @cycles:      bounded (~80 round bodies × ~130 instructions + 80-word
#               schedule + I/O ≈ 16K instructions)
# @ct:          required
# @spec:        FIPS 180-4 §6.4.2 (SHA-512 hash computation)
# @verify:      proofs/crypto/sha512/SHA512Compress.cry, proofs/crypto/sha512/sha512_compress.saw
# @tests:       tests/crypto/sha512/test_sha512_kat.py
#               (Tier A: SAW + Cryptol discharge the FIPS 180-4 §C.1
#               (abc) and SHA-512("") single-block KATs symbolically
#               over the full 80-round transform + schedule, plus the
#               6-point K-table boundary and ROTR/ch/maj algebraic
#               sanity checks. Tier C bridge: the QEMU pytest cross-
#               checks the asm against hashlib.sha512 across empty /
#               single-block / cross-block-boundary / two-padding-block
#               / multi-block inputs — angr's pcode RV32IMC engine
#               struggles with the (lo, hi) register-pair 64-bit ops,
#               so binary equivalence waits on the macaw-riscv path
#               described in ADR-0009 §"Tier C path forward".)
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* SHA-512 compression function — FIPS 180-4 §6.4.2.
 *
 * 64-bit working state on a 32-bit ISA. Each 64-bit value is stored as
 * a pair of 32-bit words in little-endian order (low word at offset,
 * high word at offset + 4). The 8 working variables a..h plus the
 * 80-word message schedule live on the stack throughout the round
 * loop; a thin set of registers shuttles the per-round computation.
 *
 * Stack frame (768 bytes, 16-byte aligned):
 *    0..639   W[80] message schedule (each entry 8 bytes)
 *  640..703   working state (a..h; 8 × 8 bytes; a@640, h@696)
 *  704..735   pad
 *  736..759   saved s0..s5 (6 × 4)
 *  760..763   pad
 *  764..767   ra
 *
 * Register allocation:
 *   s0 = ctx_ptr (preserved through the round loop)
 *   s1 = round counter t (0..79)
 *   s2 = K base   (rodata)
 *   s3 = W base   (= sp)
 *   s4 = state base (= sp + STATE_OFF = sp + 640)
 *   t0..t6, a3..a7 = scratch for 64-bit ops
 *
 * 64-bit ops on RV32 — naming: foo64(dst_lo, dst_hi, ...) takes/returns
 * a pair of registers.
 *
 * Round body (per FIPS 180-4 §6.4.2 step 3):
 *   T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
 *   T2 = Sigma0(a) + Maj(a,b,c)
 *   h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2
 *
 * Where:
 *   Ch(x,y,z)  = (x & y) ^ (~x & z)
 *   Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
 *   Sigma0(x)  = ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39)
 *   Sigma1(x)  = ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41)
 *   sigma0(x)  = ROTR(x,1)  ^ ROTR(x,8)  ^ SHR(x,7)
 *   sigma1(x)  = ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)
 *
 * For the sigma functions in the W-schedule (for t in 16..79):
 *   W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16].
 */

        .include "sha512.S"

        .equ W_OFF,       0
        .equ STATE_OFF, 640
        .equ S0_OFF,    736
        .equ S1_OFF,    740
        .equ S2_OFF,    744
        .equ S3_OFF,    748
        .equ S4_OFF,    752
        .equ S5_OFF,    756
        .equ RA_OFF,    764
        .equ FRAME,     768

        # State offsets within the 64-byte state block (a@0, b@8, ..., h@56).
        .equ A_LO,  STATE_OFF +  0
        .equ A_HI,  STATE_OFF +  4
        .equ B_LO,  STATE_OFF +  8
        .equ B_HI,  STATE_OFF + 12
        .equ C_LO,  STATE_OFF + 16
        .equ C_HI,  STATE_OFF + 20
        .equ D_LO,  STATE_OFF + 24
        .equ D_HI,  STATE_OFF + 28
        .equ E_LO,  STATE_OFF + 32
        .equ E_HI,  STATE_OFF + 36
        .equ F_LO,  STATE_OFF + 40
        .equ F_HI,  STATE_OFF + 44
        .equ G_LO,  STATE_OFF + 48
        .equ G_HI,  STATE_OFF + 52
        .equ H_LO,  STATE_OFF + 56
        .equ H_HI,  STATE_OFF + 60

        # ----- K table (80 64-bit constants, lo/hi pairs) -----
        .section .rodata.sha512_k, "a"
        .global sha512_k
        .balign 8
sha512_k:
        .word 0xd728ae22, 0x428a2f98
        .word 0x23ef65cd, 0x71374491
        .word 0xec4d3b2f, 0xb5c0fbcf
        .word 0x8189dbbc, 0xe9b5dba5
        .word 0xf348b538, 0x3956c25b
        .word 0xb605d019, 0x59f111f1
        .word 0xaf194f9b, 0x923f82a4
        .word 0xda6d8118, 0xab1c5ed5
        .word 0xa3030242, 0xd807aa98
        .word 0x45706fbe, 0x12835b01
        .word 0x4ee4b28c, 0x243185be
        .word 0xd5ffb4e2, 0x550c7dc3
        .word 0xf27b896f, 0x72be5d74
        .word 0x3b1696b1, 0x80deb1fe
        .word 0x25c71235, 0x9bdc06a7
        .word 0xcf692694, 0xc19bf174
        .word 0x9ef14ad2, 0xe49b69c1
        .word 0x384f25e3, 0xefbe4786
        .word 0x8b8cd5b5, 0x0fc19dc6
        .word 0x77ac9c65, 0x240ca1cc
        .word 0x592b0275, 0x2de92c6f
        .word 0x6ea6e483, 0x4a7484aa
        .word 0xbd41fbd4, 0x5cb0a9dc
        .word 0x831153b5, 0x76f988da
        .word 0xee66dfab, 0x983e5152
        .word 0x2db43210, 0xa831c66d
        .word 0x98fb213f, 0xb00327c8
        .word 0xbeef0ee4, 0xbf597fc7
        .word 0x3da88fc2, 0xc6e00bf3
        .word 0x930aa725, 0xd5a79147
        .word 0xe003826f, 0x06ca6351
        .word 0x0a0e6e70, 0x14292967
        .word 0x46d22ffc, 0x27b70a85
        .word 0x5c26c926, 0x2e1b2138
        .word 0x5ac42aed, 0x4d2c6dfc
        .word 0x9d95b3df, 0x53380d13
        .word 0x8baf63de, 0x650a7354
        .word 0x3c77b2a8, 0x766a0abb
        .word 0x47edaee6, 0x81c2c92e
        .word 0x1482353b, 0x92722c85
        .word 0x4cf10364, 0xa2bfe8a1
        .word 0xbc423001, 0xa81a664b
        .word 0xd0f89791, 0xc24b8b70
        .word 0x0654be30, 0xc76c51a3
        .word 0xd6ef5218, 0xd192e819
        .word 0x5565a910, 0xd6990624
        .word 0x5771202a, 0xf40e3585
        .word 0x32bbd1b8, 0x106aa070
        .word 0xb8d2d0c8, 0x19a4c116
        .word 0x5141ab53, 0x1e376c08
        .word 0xdf8eeb99, 0x2748774c
        .word 0xe19b48a8, 0x34b0bcb5
        .word 0xc5c95a63, 0x391c0cb3
        .word 0xe3418acb, 0x4ed8aa4a
        .word 0x7763e373, 0x5b9cca4f
        .word 0xd6b2b8a3, 0x682e6ff3
        .word 0x5defb2fc, 0x748f82ee
        .word 0x43172f60, 0x78a5636f
        .word 0xa1f0ab72, 0x84c87814
        .word 0x1a6439ec, 0x8cc70208
        .word 0x23631e28, 0x90befffa
        .word 0xde82bde9, 0xa4506ceb
        .word 0xb2c67915, 0xbef9a3f7
        .word 0xe372532b, 0xc67178f2
        .word 0xea26619c, 0xca273ece
        .word 0x21c0c207, 0xd186b8c7
        .word 0xcde0eb1e, 0xeada7dd6
        .word 0xee6ed178, 0xf57d4f7f
        .word 0x72176fba, 0x06f067aa
        .word 0xa2c898a6, 0x0a637dc5
        .word 0xbef90dae, 0x113f9804
        .word 0x131c471b, 0x1b710b35
        .word 0x23047d84, 0x28db77f5
        .word 0x40c72493, 0x32caab7b
        .word 0x15c9bebc, 0x3c9ebe0a
        .word 0x9c100d4c, 0x431d67c4
        .word 0xcb3e42b6, 0x4cc5d4be
        .word 0xfc657e2a, 0x597f299c
        .word 0x3ad6faec, 0x5fcb6fab
        .word 0x4a475817, 0x6c44198c

        # ===========================================================
        # Macros — 64-bit pseudo-ops on (lo, hi) register pairs
        # ===========================================================

        # ADD64 lo, hi, src_lo, src_hi : (lo, hi) += (src_lo, src_hi).
        # Uses one extra scratch register `\tmp`.
        .macro ADD64 lo, hi, src_lo, src_hi, tmp
        add     \lo, \lo, \src_lo
        sltu    \tmp, \lo, \src_lo
        add     \hi, \hi, \src_hi
        add     \hi, \hi, \tmp
        .endm

        # XOR64 lo, hi, src_lo, src_hi
        .macro XOR64 lo, hi, src_lo, src_hi
        xor     \lo, \lo, \src_lo
        xor     \hi, \hi, \src_hi
        .endm

        # MV64 dst_lo, dst_hi, src_lo, src_hi
        .macro MV64 dst_lo, dst_hi, src_lo, src_hi
        mv      \dst_lo, \src_lo
        mv      \dst_hi, \src_hi
        .endm

        # ROTR64_LT32 dst_lo, dst_hi, src_lo, src_hi, n  (1 ≤ n ≤ 31)
        # Right-rotate (src_hi:src_lo) by n bits → (dst_hi:dst_lo).
        # Uses two scratch regs `\t1` and `\t2`.
        .macro ROTR64_LT32 dst_lo, dst_hi, src_lo, src_hi, n, t1, t2
        srli    \t1, \src_lo, \n
        slli    \t2, \src_hi, (32 - \n)
        or      \dst_lo, \t1, \t2
        srli    \t1, \src_hi, \n
        slli    \t2, \src_lo, (32 - \n)
        or      \dst_hi, \t1, \t2
        .endm

        # ROTR64_GE32 dst_lo, dst_hi, src_lo, src_hi, n  (32 ≤ n ≤ 63)
        # Equivalent to swap halves then ROTR_LT32 by (n - 32).
        .macro ROTR64_GE32 dst_lo, dst_hi, src_lo, src_hi, n, t1, t2
        # Effective shift m = n - 32; rotate (lo, hi) treated as (hi, lo).
        # rot_lo = (src_hi >> m) | (src_lo << (32 - m))
        # rot_hi = (src_lo >> m) | (src_hi << (32 - m))
        .if (\n) == 32
        mv      \dst_lo, \src_hi
        mv      \dst_hi, \src_lo
        .else
        srli    \t1, \src_hi, ((\n) - 32)
        slli    \t2, \src_lo, (64 - (\n))
        or      \dst_lo, \t1, \t2
        srli    \t1, \src_lo, ((\n) - 32)
        slli    \t2, \src_hi, (64 - (\n))
        or      \dst_hi, \t1, \t2
        .endif
        .endm

        # SHR64_LT32 dst_lo, dst_hi, src_lo, src_hi, n   (1 ≤ n ≤ 31)
        # Logical right-shift the 64-bit word by n.
        .macro SHR64_LT32 dst_lo, dst_hi, src_lo, src_hi, n, t1
        srli    \t1, \src_lo, \n
        slli    \dst_hi, \src_hi, (32 - \n)
        or      \dst_lo, \t1, \dst_hi
        srli    \dst_hi, \src_hi, \n
        .endm

        # ===========================================================
        # Function body
        # ===========================================================

        .section .text.sha512_compress, "ax", @progbits
        .global sha512_compress
        .type   sha512_compress, @function
sha512_compress:
        addi    sp, sp, -FRAME
        sw      s0, S0_OFF(sp)
        sw      s1, S1_OFF(sp)
        sw      s2, S2_OFF(sp)
        sw      s3, S3_OFF(sp)
        sw      s4, S4_OFF(sp)
        sw      s5, S5_OFF(sp)
        sw      ra, RA_OFF(sp)

        mv      s0, a0                          /* save ctx_ptr           */
        la      s2, sha512_k                    /* K base                 */
        addi    s3, sp, W_OFF                   /* W base                 */
        addi    s4, sp, STATE_OFF               /* state base             */

        # ---- 1. W[0..15]: BE 64-bit load from block_ptr (a1) ----
        # Each 64-bit word is 8 BE bytes. The HIGH 4 bytes come first
        # in the byte stream (FIPS 180-4 BE ordering); we store them
        # at offset+4 in our LE pair layout.
        mv      t0, s3                          /* W cursor               */
        mv      t1, a1                          /* M cursor               */
        li      t6, 16                          /* counter                */
.Lload_w:
        # High 32 bits (bytes 0..3 of message word) → W[i].hi at +4
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
        sw      t2, 4(t0)
        # Low 32 bits (bytes 4..7) → W[i].lo at +0
        lbu     t2, 4(t1)
        lbu     t3, 5(t1)
        lbu     t4, 6(t1)
        lbu     t5, 7(t1)
        slli    t2, t2, 24
        slli    t3, t3, 16
        slli    t4, t4, 8
        or      t2, t2, t3
        or      t2, t2, t4
        or      t2, t2, t5
        sw      t2, 0(t0)
        addi    t0, t0, 8
        addi    t1, t1, 8
        addi    t6, t6, -1
        bnez    t6, .Lload_w

        # ---- 2. W[16..79] schedule ----
        # W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
        addi    t0, s3, 16*8                    /* &W[16]                 */
        li      s5, 64                          /* iters: 80 - 16         */
.Lschedule:
        /* Compute sigma1(W[t-2]) into (a3, a4).
         * sigma1(x) = ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)
         * In (lo, hi) pairs:
         *   src = W[t-2] at offset (t0 - 16) → lo at 0, hi at 4
         */
        lw      a5, -16(t0)                     /* W[t-2].lo              */
        lw      a6, -12(t0)                     /* W[t-2].hi              */

        ROTR64_LT32 a3, a4, a5, a6, 19, t1, t2  /* a4:a3 = ROTR_19         */
        ROTR64_GE32 t3, t4, a5, a6, 61, t1, t2  /* t4:t3 = ROTR_61         */
        XOR64       a3, a4, t3, t4               /* a4:a3 ^= ROTR_61       */
        SHR64_LT32  t3, t4, a5, a6, 6, t1        /* t4:t3 = SHR_6          */
        XOR64       a3, a4, t3, t4

        /* Add W[t-7] (offset -56). */
        lw      t1, -56(t0)
        lw      t2, -52(t0)
        ADD64   a3, a4, t1, t2, t3

        /* sigma0(W[t-15]) into (a5, a6). */
        lw      a5, -120(t0)                    /* W[t-15].lo             */
        lw      a6, -116(t0)                    /* W[t-15].hi             */

        ROTR64_LT32 a7, t6, a5, a6, 1, t1, t2   /* (t6:a7) = ROTR_1        */
        ROTR64_LT32 t3, t4, a5, a6, 8, t1, t2   /* (t4:t3) = ROTR_8        */
        XOR64       a7, t6, t3, t4
        SHR64_LT32  t3, t4, a5, a6, 7, t1
        XOR64       a7, t6, t3, t4

        /* Sum sigma0 into accumulator (a4:a3). */
        ADD64   a3, a4, a7, t6, t1

        /* Add W[t-16] (offset -128). */
        lw      t1, -128(t0)
        lw      t2, -124(t0)
        ADD64   a3, a4, t1, t2, t3

        /* Store W[t] = (a4:a3). */
        sw      a3, 0(t0)
        sw      a4, 4(t0)

        addi    t0, t0, 8
        addi    s5, s5, -1
        bnez    s5, .Lschedule

        # ---- 3. Initialise working state from H ----
        # state_a..state_h := H[0..7]
        mv      t0, s0                          /* &H                     */
        mv      t1, s4                          /* &state                 */
        li      t6, 16                          /* 16 32-bit copies       */
.Linit_state:
        lw      t2, 0(t0)
        sw      t2, 0(t1)
        addi    t0, t0, 4
        addi    t1, t1, 4
        addi    t6, t6, -1
        bnez    t6, .Linit_state

        # ---- 4. 80-round main loop ----
        li      s1, 0                           /* round counter t        */
.Lround:
        /* Load e (lo, hi) into (t0, t1). */
        lw      t0, E_LO(sp)
        lw      t1, E_HI(sp)

        /* Sigma1(e) = ROTR_14 ^ ROTR_18 ^ ROTR_41
         * Accumulate into (a3, a4). */
        ROTR64_LT32 a3, a4, t0, t1, 14, t2, t3
        ROTR64_LT32 t4, t5, t0, t1, 18, t2, t3
        XOR64       a3, a4, t4, t5
        ROTR64_GE32 t4, t5, t0, t1, 41, t2, t3
        XOR64       a3, a4, t4, t5

        /* Ch(e,f,g) = (e & f) ^ (~e & g). f, g loaded fresh. */
        lw      t2, F_LO(sp)
        lw      t3, F_HI(sp)
        and     t4, t0, t2                       /* e & f (lo)             */
        and     t5, t1, t3                       /* e & f (hi)             */
        not     t2, t0
        not     t3, t1                            /* ~e                     */
        lw      a5, G_LO(sp)
        lw      a6, G_HI(sp)
        and     t2, t2, a5                       /* (~e) & g (lo)          */
        and     t3, t3, a6                       /* (~e) & g (hi)          */
        xor     t4, t4, t2                       /* Ch (lo)                */
        xor     t5, t5, t3                       /* Ch (hi)                */
        ADD64   a3, a4, t4, t5, t2               /* Sigma1 + Ch            */

        /* Add h. */
        lw      t4, H_LO(sp)
        lw      t5, H_HI(sp)
        ADD64   a3, a4, t4, t5, t2

        /* Add K[t]. */
        slli    t4, s1, 3                        /* offset = t * 8         */
        add     t4, s2, t4                       /* &K[t]                  */
        lw      a5, 0(t4)
        lw      a6, 4(t4)
        ADD64   a3, a4, a5, a6, t2

        /* Add W[t]. */
        slli    t4, s1, 3
        add     t4, s3, t4                       /* &W[t]                  */
        lw      a5, 0(t4)
        lw      a6, 4(t4)
        ADD64   a3, a4, a5, a6, t2
        /* (a4:a3) = T1 */

        /* Sigma0(a) = ROTR_28 ^ ROTR_34 ^ ROTR_39
         * Accumulate into (a5, a6). */
        lw      t0, A_LO(sp)
        lw      t1, A_HI(sp)
        ROTR64_LT32 a5, a6, t0, t1, 28, t2, t3
        ROTR64_GE32 t4, t5, t0, t1, 34, t2, t3
        XOR64       a5, a6, t4, t5
        ROTR64_GE32 t4, t5, t0, t1, 39, t2, t3
        XOR64       a5, a6, t4, t5

        /* Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c).
         * a still in (t0, t1). Load b → (t2, t3), c → (a7, t6).
         * Accumulator for Maj in (t4, t5). */
        lw      t2, B_LO(sp)
        lw      t3, B_HI(sp)
        and     t4, t0, t2                       /* a & b (lo)             */
        and     t5, t1, t3                       /* a & b (hi)             */
        lw      a7, C_LO(sp)
        lw      t6, C_HI(sp)
        and     t2, t2, a7                       /* b & c (lo) — reuses b  */
        and     t3, t3, t6                       /* b & c (hi)             */
        xor     t4, t4, t2                       /* (a&b) ^ (b&c) (lo)     */
        xor     t5, t5, t3                       /* (a&b) ^ (b&c) (hi)     */
        and     t2, t0, a7                       /* a & c (lo)             */
        and     t3, t1, t6                       /* a & c (hi)             */
        xor     t4, t4, t2                       /* Maj (lo)               */
        xor     t5, t5, t3                       /* Maj (hi)               */

        ADD64   a5, a6, t4, t5, t2               /* (a6:a5) = T2           */

        /* State shift: h = g; g = f; f = e; e = d + T1; d = c; c = b;
         * b = a; a = T1 + T2.
         * To minimise stack churn, do the assignments in the order that
         * lets each load happen exactly once. We already have d in
         * memory; load it, add T1, store as new e. Similarly load
         * (T1, T2) → new a. */

        /* h = g */
        lw      t0, G_LO(sp)
        lw      t1, G_HI(sp)
        sw      t0, H_LO(sp)
        sw      t1, H_HI(sp)

        /* g = f */
        lw      t0, F_LO(sp)
        lw      t1, F_HI(sp)
        sw      t0, G_LO(sp)
        sw      t1, G_HI(sp)

        /* f = e */
        lw      t0, E_LO(sp)
        lw      t1, E_HI(sp)
        sw      t0, F_LO(sp)
        sw      t1, F_HI(sp)

        /* e = d + T1   (T1 still in (a4:a3)) */
        lw      t0, D_LO(sp)
        lw      t1, D_HI(sp)
        ADD64   t0, t1, a3, a4, t2
        sw      t0, E_LO(sp)
        sw      t1, E_HI(sp)

        /* d = c */
        lw      t0, C_LO(sp)
        lw      t1, C_HI(sp)
        sw      t0, D_LO(sp)
        sw      t1, D_HI(sp)

        /* c = b */
        lw      t0, B_LO(sp)
        lw      t1, B_HI(sp)
        sw      t0, C_LO(sp)
        sw      t1, C_HI(sp)

        /* b = a */
        lw      t0, A_LO(sp)
        lw      t1, A_HI(sp)
        sw      t0, B_LO(sp)
        sw      t1, B_HI(sp)

        /* a = T1 + T2 = (a4:a3) + (a6:a5) */
        ADD64   a3, a4, a5, a6, t2
        sw      a3, A_LO(sp)
        sw      a4, A_HI(sp)

        addi    s1, s1, 1
        li      t0, SHA512_ROUNDS
        bne     s1, t0, .Lround

        # ---- 5. H[i] += state[i] (16 32-bit additions, with carry) ----
        # For each 64-bit pair (state.lo, state.hi) → ctx->H[i] += ...
        mv      t0, s0                          /* &H                     */
        mv      t1, s4                          /* &state                 */
        li      t6, 8                           /* 8 64-bit additions     */
.Lfinal:
        lw      t2, 0(t0)                       /* H[i].lo                */
        lw      t3, 4(t0)                       /* H[i].hi                */
        lw      t4, 0(t1)                       /* state[i].lo            */
        lw      t5, 4(t1)                       /* state[i].hi            */
        add     a3, t2, t4
        sltu    a4, a3, t4                      /* carry                  */
        add     t3, t3, t5
        add     t3, t3, a4
        sw      a3, 0(t0)
        sw      t3, 4(t0)
        addi    t0, t0, 8
        addi    t1, t1, 8
        addi    t6, t6, -1
        bnez    t6, .Lfinal

        lw      s0, S0_OFF(sp)
        lw      s1, S1_OFF(sp)
        lw      s2, S2_OFF(sp)
        lw      s3, S3_OFF(sp)
        lw      s4, S4_OFF(sp)
        lw      s5, S5_OFF(sp)
        lw      ra, RA_OFF(sp)
        addi    sp, sp, FRAME
        ret

        .size   sha512_compress, . - sha512_compress
