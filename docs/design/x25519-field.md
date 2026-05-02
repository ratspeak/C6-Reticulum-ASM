# X25519 field arithmetic — design

## Field representation

X25519 field elements live in GF(p) where `p = 2^255 - 19`. The internal
representation is 10 signed 32-bit limbs in **radix 2^25.5** (the
curve25519-donna 32-bit form, also used by BearSSL and ref10). Each
field element occupies 40 bytes (`10 × int32`) in memory.

Limb weights (signed bit budget given as `k bits` is the nominal width
that lets sums and partial products accumulate in int32 without
overflow):

| limb | weight       | nominal width |
|------|--------------|---------------|
| f[0] | 2^0   = 1    | 26 bits       |
| f[1] | 2^26         | 25 bits       |
| f[2] | 2^51         | 26 bits       |
| f[3] | 2^77         | 25 bits       |
| f[4] | 2^102        | 26 bits       |
| f[5] | 2^128        | 25 bits       |
| f[6] | 2^153        | 26 bits       |
| f[7] | 2^179        | 25 bits       |
| f[8] | 2^204        | 26 bits       |
| f[9] | 2^230        | 25 bits       |

The integer represented by an element is
`sum_i f[i] * 2^(25.5 * i) (mod p)`. Different limb arrays can encode
the same field element; canonicality is enforced only at pack/unpack
boundaries.

## Why radix 2^25.5

- Each limb fits comfortably in `int32` after a single multiply: a
  product of two 26-bit values is 52 bits, well within int64 used as
  the multiply accumulator. Ten limbs * ten limbs = 100 word
  multiplies plus carries, all in 64-bit accumulators.
- Add and sub are bare 10-limb pointwise operations. The result limbs
  may grow by one bit per add — many adds can compose before a carry
  is needed.
- Reduction mod `p` folds neatly: after carry-propagation the top
  limb's overflow folds back into limb 0 with weight 19 (since
  `2^255 ≡ 19 (mod p)`).
- This is the canonical 32-bit X25519 representation. Compatible with
  curve25519-donna, BearSSL (`br_curve25519_i31`), Bernstein's ref10,
  and every published reference implementation. Verification can
  cross-check against any of them.

## ABI for field functions

All field functions follow the project ABI (RISC-V psABI ILP32, ADR-0001):

```
void x25519_field_<op>(int32_t *out, const int32_t *a, const int32_t *b);
                       a0           a1                a2
```

with `out`, `a`, `b` each pointing to a 40-byte (10×int32) buffer. The
`out` buffer may overlap with `a` or `b` (in-place is supported).

- `x25519_field_add(out, a, b)` — `out = a + b` (pointwise).
- `x25519_field_sub(out, a, b)` — `out = a - b` (pointwise; signed).
- `x25519_field_mul(out, a, b)` — `out = a * b mod p` (with reduction).
- `x25519_field_sq(out, a)`     — same as `mul(out, a, a)` but
  optimised (about 2× faster).
- `x25519_field_mul121665(out, a)` — `out = 121665 * a mod p`. Single-
  limb multiplier for the Montgomery ladder's `a24` step.
- `x25519_field_inv(out, a)`    — `out = a^(p - 2) mod p` via Fermat.
- `x25519_field_pack(out_bytes, a)` — canonical 32-byte little-endian.
- `x25519_field_unpack(out, in_bytes)` — read 32 LE bytes (with the
  RFC 7748 §5 `u`-coordinate high-bit mask applied externally if the
  caller is decoding a u-coordinate; pure unpack does no masking).

## Pack/unpack canonicality

`pack` takes a non-canonical 10-limb representation (limbs may have
grown beyond their nominal width through arithmetic) and emits the
**unique** canonical 32-byte little-endian encoding `n mod p` where
`0 ≤ n < p`. The procedure is curve25519-donna's `fcontract`:
carry-propagate three times to bring each limb into nominal width,
conditional-subtract `p` once if the result is `≥ p`, then pack.

`unpack` is the inverse (no reduction needed since input is `< 2^256`):
distribute the 32 bytes across the 10 limbs at their bit weights, with
no clamping. Caller does any RFC 7748 high-bit mask before calling.

## Verification strategy

Per ADR-0009:

- **Tier A (Cryptol + SAW)**: a single `X25519FieldOps.cry` module
  defines the field representation as an Integer-valued `decode_limbs`
  function plus pure-Integer `f_add` / `f_sub` / `f_mul` etc. The
  bridge between asm and Cryptol is the equation:
  `decode_limbs (asm_op a b) == cryptol_op (decode_limbs a) (decode_limbs b)`
  for each op. SAW discharges these as algebraic identities.

- **Tier C (angr)**: per-function `.py` verifier loads firmware ELF,
  drives the asm with concrete-but-varied limb arrays (random + edge
  cases including limbs at their range bounds), and asserts the
  decoded integer matches the Python oracle. Limbs of `out` are NOT
  required to be canonical — comparison is on the integer they
  represent.

- **Tier B (Binsec/Rel)**: secret-handling field ops (notably `f_mul`
  and `f_inv` which operate on private scalars during the ladder)
  carry a `.bsc` driver tagging input limbs as secret and asserting
  no secret-dependent control flow or memory access. Add/sub/cswap are
  trivially constant-time by construction.

For `f_mul` in particular: angr's pcode RV32IMC engine will likely
miscompile the asm (same Boyar-Peralta pattern that bit AES). Tier A +
the existing pytest QEMU KAT carry the binary-correctness obligation
until SAW + macaw-riscv lands per ADR-0009 §"Tier C path forward".

## Why not radix 2^51 (5 limbs of 51 bits)?

Used by 64-bit donna and HACL\* on AArch64. Inappropriate here:
- We're on RV32, no native 64-bit registers.
- A 51-bit limb requires 64-bit storage and 64-bit multiplies; on RV32
  these become 2-instruction sequences for every operation, eliminating
  the storage advantage.
- Multiplication products would need 128-bit accumulators emulated.
- Radix 2^25.5 is purpose-built for 32-bit ISAs; we honor that.

## Why not fiat-crypto generation?

Fiat-crypto's `curve25519_32.c` is verified-by-construction Coq output
and would be the formally cleanest path — it could be hand-translated
to RV32 asm with very low bug risk. ADR-0009 names this as a future
option (the file is vendored at `references/fiat-crypto/fiat-c/src/
curve25519_32.c`). Reasons we hand-write instead, for now:
- Donna 32-bit is shorter and more readable as asm than fiat-crypto's
  generated form (which optimises for C compilers, not human
  inspection).
- Our verifier stack already proves Cryptol equivalence directly; the
  fiat-crypto Coq proof is overkill *given that we re-verify*.
- A fiat-crypto port is a credible alternative implementation we can
  switch to later if our hand-written form has performance or
  verifiability issues.
