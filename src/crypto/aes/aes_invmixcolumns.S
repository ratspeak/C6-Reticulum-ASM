# ============================================================================
# @function:    aes_invmixcolumns
# @module:      crypto/aes
# @inputs:      a0 = state ptr (16 bytes)
# @outputs:     each 4-byte column is multiplied by the AES inverse-MDS
#               matrix (FIPS 197 §5.3.3) in place
# @clobbers:    t0..t6, a0..a4, ra
# @preserves:   sp, gp, s0, s1 (saved/restored)
# @stack:       32
# @cycles:      bounded (~700; 4 column iterations)
# @ct:          required (xtime is branch-free; loop is data-independent)
# @spec:        FIPS 197 §5.3.3 (InvMixColumns) using
#                 14*x = (2x)^(4x)^(8x)
#                 13*x = x^(4x)^(8x)
#                 11*x = x^(2x)^(8x)
#                  9*x = x^(8x)
#               where the (2x), (4x), (8x) chain is built by repeated
#               constant-time xtime (poly 0x1B reduction).
# @verify:      proofs/crypto/aes/AES256.cry, proofs/crypto/aes/aes256.saw
# @tests:       tests/crypto/aes/test_aes_mixcolumns.py
# @adrs:        0001, 0002, 0006, 0009
# @status:      verified
# ============================================================================

/* InvMixColumns is the matrix-multiply analogue of MixColumns under
 * the inverse MDS matrix [0E 0B 0D 09; 09 0E 0B 0D; 0D 09 0E 0B;
 * 0B 0D 09 0E].  We compute the per-byte multiples 2*x, 4*x, 8*x with
 * three repeated xtime invocations and combine them per the formulas
 * above.
 *
 * Stack layout: 32 bytes.
 *   0(sp)  ra
 *   4(sp)  saved s0   (column cursor)
 *   8(sp)  saved s1   (end ptr)
 *  12(sp)  pad
 *  16..19  s_i        (1*x for i=0..3)
 *  20..23  s_i*2
 *  24..27  s_i*4
 *  28..31  s_i*8
 *
 * Constant-time by construction.  See xtime derivation in
 * aes_mixcolumns.S.
 */

        .include "aes.S"

        .equ FSZ,        32
        .equ X1_OFF,     16
        .equ X2_OFF,     20
        .equ X4_OFF,     24
        .equ X8_OFF,     28

        /* Inline xtime macro: dst = xtime(src) using a0, a1 as scratch. */
        .macro XT dst:req, src:req
        srli    a0, \src, 7
        neg     a0, a0
        andi    a0, a0, AES_GF_MOD_BYTE
        slli    a1, \src, 1
        andi    a1, a1, 0xff
        xor     \dst, a1, a0
        .endm

        .section .text.aes_invmixcolumns, "ax", @progbits
        .global aes_invmixcolumns
        .type   aes_invmixcolumns, @function
aes_invmixcolumns:
        addi    sp, sp, -FSZ
        sw      ra, 0(sp)
        sw      s0, 4(sp)
        sw      s1, 8(sp)

        mv      s0, a0
        addi    s1, a0, AES_BLOCK_SIZE

.Limc_loop:
        /* Load 4 column bytes into t0..t3 and into the work area at
         * X1_OFF..X1_OFF+3. */
        lbu     t0, 0(s0)
        lbu     t1, 1(s0)
        lbu     t2, 2(s0)
        lbu     t3, 3(s0)
        sb      t0, X1_OFF+0(sp)
        sb      t1, X1_OFF+1(sp)
        sb      t2, X1_OFF+2(sp)
        sb      t3, X1_OFF+3(sp)

        /* xtime chain: 2*s_i in t0..t3, store at X2_OFF */
        XT      t0, t0
        XT      t1, t1
        XT      t2, t2
        XT      t3, t3
        sb      t0, X2_OFF+0(sp)
        sb      t1, X2_OFF+1(sp)
        sb      t2, X2_OFF+2(sp)
        sb      t3, X2_OFF+3(sp)

        /* 4*s_i in t0..t3, store at X4_OFF */
        XT      t0, t0
        XT      t1, t1
        XT      t2, t2
        XT      t3, t3
        sb      t0, X4_OFF+0(sp)
        sb      t1, X4_OFF+1(sp)
        sb      t2, X4_OFF+2(sp)
        sb      t3, X4_OFF+3(sp)

        /* 8*s_i in t0..t3, store at X8_OFF */
        XT      t0, t0
        XT      t1, t1
        XT      t2, t2
        XT      t3, t3
        sb      t0, X8_OFF+0(sp)
        sb      t1, X8_OFF+1(sp)
        sb      t2, X8_OFF+2(sp)
        sb      t3, X8_OFF+3(sp)

        /* Now assemble new bytes from the (1, 2, 4, 8)*s_i tables.
         *   new_s0 = 14*s0 ^ 11*s1 ^ 13*s2 ^ 9*s3
         *          = (2s0^4s0^8s0) ^ (s1^2s1^8s1) ^ (s2^4s2^8s2) ^ (s3^8s3)
         *   new_s1 = 9*s0 ^ 14*s1 ^ 11*s2 ^ 13*s3
         *          = (s0^8s0) ^ (2s1^4s1^8s1) ^ (s2^2s2^8s2) ^ (s3^4s3^8s3)
         *   new_s2 = 13*s0 ^ 9*s1 ^ 14*s2 ^ 11*s3
         *          = (s0^4s0^8s0) ^ (s1^8s1) ^ (2s2^4s2^8s2) ^ (s3^2s3^8s3)
         *   new_s3 = 11*s0 ^ 13*s1 ^ 9*s2 ^ 14*s3
         *          = (s0^2s0^8s0) ^ (s1^4s1^8s1) ^ (s2^8s2) ^ (2s3^4s3^8s3)
         */

        /* new_s0 */
        lbu     t0, X2_OFF+0(sp)        /* 2s0 */
        lbu     t1, X4_OFF+0(sp)
        xor     t0, t0, t1
        lbu     t1, X8_OFF+0(sp)
        xor     t0, t0, t1              /* 14s0 */
        lbu     t1, X1_OFF+1(sp)
        lbu     t2, X2_OFF+1(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+1(sp)
        xor     t1, t1, t2              /* 11s1 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+2(sp)
        lbu     t2, X4_OFF+2(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+2(sp)
        xor     t1, t1, t2              /* 13s2 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+3(sp)
        lbu     t2, X8_OFF+3(sp)
        xor     t1, t1, t2              /* 9s3 */
        xor     t0, t0, t1
        sb      t0, 0(s0)

        /* new_s1 */
        lbu     t0, X1_OFF+0(sp)
        lbu     t1, X8_OFF+0(sp)
        xor     t0, t0, t1              /* 9s0 */
        lbu     t1, X2_OFF+1(sp)
        lbu     t2, X4_OFF+1(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+1(sp)
        xor     t1, t1, t2              /* 14s1 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+2(sp)
        lbu     t2, X2_OFF+2(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+2(sp)
        xor     t1, t1, t2              /* 11s2 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+3(sp)
        lbu     t2, X4_OFF+3(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+3(sp)
        xor     t1, t1, t2              /* 13s3 */
        xor     t0, t0, t1
        sb      t0, 1(s0)

        /* new_s2 */
        lbu     t0, X1_OFF+0(sp)
        lbu     t1, X4_OFF+0(sp)
        xor     t0, t0, t1
        lbu     t1, X8_OFF+0(sp)
        xor     t0, t0, t1              /* 13s0 */
        lbu     t1, X1_OFF+1(sp)
        lbu     t2, X8_OFF+1(sp)
        xor     t1, t1, t2              /* 9s1 */
        xor     t0, t0, t1
        lbu     t1, X2_OFF+2(sp)
        lbu     t2, X4_OFF+2(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+2(sp)
        xor     t1, t1, t2              /* 14s2 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+3(sp)
        lbu     t2, X2_OFF+3(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+3(sp)
        xor     t1, t1, t2              /* 11s3 */
        xor     t0, t0, t1
        sb      t0, 2(s0)

        /* new_s3 */
        lbu     t0, X1_OFF+0(sp)
        lbu     t1, X2_OFF+0(sp)
        xor     t0, t0, t1
        lbu     t1, X8_OFF+0(sp)
        xor     t0, t0, t1              /* 11s0 */
        lbu     t1, X1_OFF+1(sp)
        lbu     t2, X4_OFF+1(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+1(sp)
        xor     t1, t1, t2              /* 13s1 */
        xor     t0, t0, t1
        lbu     t1, X1_OFF+2(sp)
        lbu     t2, X8_OFF+2(sp)
        xor     t1, t1, t2              /* 9s2 */
        xor     t0, t0, t1
        lbu     t1, X2_OFF+3(sp)
        lbu     t2, X4_OFF+3(sp)
        xor     t1, t1, t2
        lbu     t2, X8_OFF+3(sp)
        xor     t1, t1, t2              /* 14s3 */
        xor     t0, t0, t1
        sb      t0, 3(s0)

        addi    s0, s0, 4
        bltu    s0, s1, .Limc_loop

        lw      ra, 0(sp)
        lw      s0, 4(sp)
        lw      s1, 8(sp)
        addi    sp, sp, FSZ
        ret

        .size   aes_invmixcolumns, . - aes_invmixcolumns
