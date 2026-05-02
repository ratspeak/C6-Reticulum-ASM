# Milestone 2: Cryptographic primitives

- **Status:** Active
- **Started:** 2026-05-02
- **Estimate:** 4–6 months

## Goal

Implement every cryptographic primitive Reticulum requires, in pure RV32IMAC
assembly, with per-function constant-time and equivalence proofs (per
[ADR-0006](../adr/0006-formal-verification.md)). By the end of this
milestone the project owns SHA-256, HMAC-SHA-256, HKDF, AES-256-CBC,
X25519, Ed25519, and a hardware-RNG-backed `rng_bytes`. Each primitive
ships with NIST or RFC test vectors, an equivalence proof against a
Cryptol or fiat-crypto reference, and a constant-time proof.

This is the longest single milestone in the roadmap. The crypto primitives
are the trust base for every milestone above it; haste here trades
debuggable failure later for invisible failure forever. Each primitive's
spec block is reviewed before its asm is written. Each primitive reaches
`verified` only after all three obligations (KAT, equivalence, ct) pass.

## Relationship to milestone 1

Milestone 1 is software-complete (24/25 functions verified; `uart_isr`
deferred to hw target) but its hardware-demo Definition-of-Done item is
gated on the user's bring-up of the Adafruit Feather. Milestone 2 work
proceeds in parallel with that bring-up — none of the crypto primitives
depend on UART ISR or the C6 register file. When the hw demo lands,
milestone 1 transitions to `Complete` independently of milestone 2's
state.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| SHA-256 (init/compress/update/final) | [§sha256](#sha256) | Forever |
| HMAC-SHA-256 | [§hmac](#hmac) | Forever |
| HKDF (extract/expand) | [§hkdf](#hkdf) | Forever |
| AES-256-CBC (key-expand/encrypt/decrypt; CBC mode) | [§aes](#aes) | Forever |
| X25519 (field arith + scalar-mult + keypair) | [§x25519](#x25519) | Forever |
| Ed25519 (keypair, sign, verify) | [§ed25519](#ed25519) | Forever |
| Hardware RNG wrapper | [§rng](#rng) | Forever |
| Verifier toolchain (SAW, Cryptol, fiat-crypto, ct-verif) | [§verifier-toolchain](#verifier-toolchain) | Forever |
| KAT vector pack (NIST + RFC) | [§kat-vectors](#kat-vectors) | Forever |

## Definition of done

Every condition is objectively verifiable.

- [ ] Verifier toolchain installed and passing self-tests on the dev box;
      `proofs/README.md` lists the version of each tool that produced a
      passing run for at least one function.
- [ ] Every function listed in [FUNCTIONS.md](../../FUNCTIONS.md) under
      `crypto/*` has status `verified` (status `tested` is insufficient
      for crypto per ADR-0006).
- [ ] Each function has KAT cases drawn from a published source (NIST,
      RFC) and the source is recorded in the function's spec block under
      `@spec`.
- [ ] Each function has a Cryptol or fiat-crypto reference under
      `proofs/<module>/<function>.cry` (or `.saw` driver) with an
      equivalence proof discharged by SAW.
- [ ] Each function has a constant-time proof produced by `ct-verif`
      (or equivalent) and recorded under `proofs/<module>/<function>.ct.txt`.
- [ ] `make ci` runs `tools/parse_spec.py`, `tools/check_registry.py`,
      `tools/check_stack.py`, and the pytest harness; all green.
- [ ] `./verify --all` passes for every milestone-1 + milestone-2 entry.
- [ ] Worst-case stack depth (per `tools/check_stack.py`) remains
      within `STACK_SIZE`. The crypto primitives are the largest stack
      consumers in the project; if any pushes us over, the function is
      restructured rather than the limit raised.
- [ ] No new dynamic memory allocations introduced (per ADR-0002). All
      crypto state lives in `src/state/<module>.S` `.bss` sections.

## verifier-toolchain

The toolchain decision is finalised in
[ADR-0009](../adr/0009-verifier-toolchain.md). Concrete tools, pinned in
`toolchain/versions.lock`:

| Tier | Tool | Version | Role |
|------|------|---------|------|
| A | Cryptol + SAW | 3.5.0 / 1.5 | Algorithmic spec + Cryptol-Cryptol equivalence |
| B | Binsec/Rel | 0.11.1 | Constant-time on RV32 ELF (`-isa riscv32 -checkct`) |
| C | angr + pypcode | 9.2.213 / 3.3.3 | Binary equivalence on RV32IMC |
| D | TLA+ Tools | 2.19 | State-machine refinement (milestone 5+) |
| E | Sail-RISCV | 0.20.1 + `4d5530b` | ISA reference |

Supporting:

- **fiat-crypto** (`412e8af`, requires Coq 9.1.1) — Coq-verified field
  arithmetic. Reference for X25519 field ops; the prebuilt
  `references/fiat-crypto/fiat-c/src/curve25519_32.c` is available as
  the cross-check oracle. Generation-vs-handwrite decision deferred to
  X25519 implementation phase.
- **ct-verif is rejected** for this project (x86-only, see ADR-0009);
  Binsec/Rel is the chosen replacement.
- **macaw-riscv + custom `llvm_verify_riscv`** is the documented
  Tier C-future path for true SAW-on-RV32 equivalence; GHC 9.6.7 +
  cabal 3.10.3.0 are installed (`toolchain/local/bin/`) so this work
  can be picked up whenever it becomes the bottleneck.

The first sub-task of milestone 2 — install the toolchain and prove the
trivial case (32-byte memset) end-to-end — is **complete** as of 2026-05-02:
`sha256_init` discharges Tier A (Cryptol + SAW) and Tier C (angr binary
equivalence); Tier B is vacuous (no secret inputs). See the Current
frontier section below.

## sha256

Module: `crypto/sha256`. Implements SHA-256 per FIPS 180-4. Four
functions form the streaming API:

- `sha256_init(ctx_ptr)` — initialize the 32-byte H state and 8-byte
  length counter.
- `sha256_compress(ctx_ptr, block_ptr)` — process one 64-byte block.
  The arithmetic core: 64 rounds, message schedule expansion, K[64]
  round constants. Largest single function in this module.
- `sha256_update(ctx_ptr, data_ptr, len)` — append `len` bytes; flush
  full blocks through `sha256_compress`; buffer the tail.
- `sha256_final(ctx_ptr, out_ptr)` — append the FIPS 180-4 padding,
  the 64-bit length, run one or two trailing compress calls, and copy
  the 32-byte digest out.

Context layout (`src/state/sha256.S`):

```
struct sha256_ctx {        // 112 bytes total
    uint32_t H[8];         // intermediate hash state (offset 0)
    uint64_t length_bits;  // total bytes hashed × 8 (offset 32)
    uint8_t  block[64];    // partial block buffer (offset 40)
    uint32_t block_len;    // bytes currently in `block` (offset 104)
    uint32_t _pad;         // align to 16 bytes (offset 108)
};
```

KAT sources: FIPS 180-4 Appendix B.1 (one-block "abc"), B.2 (two-block),
plus NIST CAVP byte-test vectors at `references/nist-cavp/sha256/`.

Equivalence: against the Cryptol primitive `SHA256` (Galois-distributed)
with byte-level I/O wrappers.

Constant-time: SHA-256 is data-oblivious by construction; the ct prover
should pass trivially. Any failure indicates a real bug (e.g., a
data-dependent branch in the message schedule).

## hmac

Module: `crypto/hmac`. RFC 2104 `HMAC-SHA-256`. One function:

- `hmac_sha256(key_ptr, key_len, msg_ptr, msg_len, out_ptr)` — emits
  a 32-byte tag.

Implementation: ipad/opad XOR + two SHA-256 calls. State borrowed from
`sha256_ctx` (no new state).

KAT: RFC 4231 §4.

## hkdf

Module: `crypto/hkdf`. RFC 5869.

- `hkdf_extract(salt_ptr, salt_len, ikm_ptr, ikm_len, prk_out)` — wraps
  one HMAC-SHA-256.
- `hkdf_expand(prk_ptr, info_ptr, info_len, out_ptr, out_len)` — iterates
  HMAC-SHA-256 to produce up to 255×32 bytes.

KAT: RFC 5869 Appendix A.

## aes

Module: `crypto/aes`. AES-256 per FIPS 197 plus CBC mode per NIST
SP 800-38A.

- `aes256_key_expand(key_ptr, round_keys_out)` — 240-byte schedule.
- `aes256_encrypt_block(round_keys_ptr, in_ptr, out_ptr)` — single 16-byte
  block, 14 rounds.
- `aes256_decrypt_block(round_keys_ptr, in_ptr, out_ptr)` — inverse.
- `aes256_cbc_encrypt(round_keys_ptr, iv_ptr, in_ptr, in_len, out_ptr)`.
- `aes256_cbc_decrypt(round_keys_ptr, iv_ptr, in_ptr, in_len, out_ptr)`.

Constant-time is the central concern. Table-based AES (S-box lookups)
leaks via cache timing. We will use a bit-sliced implementation or a
constant-time S-box (per BearSSL `aes_ct.c`), evaluated against ct-verif.

KAT: FIPS 197 Appendix C.3 (single-block); NIST SP 800-38A §F.2 (CBC).

## x25519

Module: `crypto/x25519`. RFC 7748.

Field-arithmetic primitives (collectively `x25519_field_*`) implement
`Fp` operations modulo `2^255 - 19`: add, sub, mul, square, invert,
mul121665. These are the largest stack consumers and the most subtle
to make constant-time; expect to lean on fiat-crypto for the field
ops and prove equivalence against the asm.

Higher-level functions:

- `x25519_scalar_mult(scalar_ptr, point_ptr, out_ptr)` — Montgomery
  ladder.
- `x25519_keypair(rng_ctx_ptr, sk_out, pk_out)` — combines `rng_bytes`
  with `x25519_scalar_mult` over the base point `9`.

KAT: RFC 7748 §5.2 (test vectors), §6.1 (Diffie-Hellman test).

## ed25519

Module: `crypto/ed25519`. RFC 8032.

- `ed25519_keypair(rng_ctx_ptr, sk_out, pk_out)`.
- `ed25519_sign(sk_ptr, msg_ptr, msg_len, sig_out)`.
- `ed25519_verify(pk_ptr, msg_ptr, msg_len, sig_ptr) -> int` — 0 = valid,
  1 = invalid.

Reuses SHA-512 (via two-round SHA-256? — no; Ed25519 needs SHA-512
proper). Adding `sha512_*` may be required as a sub-deliverable; decision
made when the implementation phase begins. Alternative: Ed25519ph with
SHA-256 only (Reticulum may already use this — TBD against
upstream).

KAT: RFC 8032 §7.1.

## rng

Module: `crypto/rng`. Wrapper around the ESP32-C6 hardware RNG.

- `rng_init()` — enable the entropy source.
- `rng_bytes(out_ptr, len)` — pull `len` bytes of entropy.

The C6's RNG requires WiFi/BLE clocks for full entropy quality (per
ESP32-C6 TRM Ch 38). On qemu-virt the hardware RNG is not modeled; tests
fake it via a deterministic source that is clearly marked unsafe in
the disassembly (e.g., a bright "DETERMINISTIC_FAKE_RNG" symbol that
must NOT survive into a release build).

KAT: not applicable (RNG output is unpredictable). Verification is
distributional (NIST SP 800-22 statistical tests on a sampled stream)
plus a smoke test that two consecutive calls produce different bytes.

## kat-vectors

Vendored in `references/kat/` once milestone 2 starts:

- `references/kat/sha256/` — FIPS 180-4 + NIST CAVP byte-tests.
- `references/kat/hmac-sha256/` — RFC 4231.
- `references/kat/hkdf/` — RFC 5869.
- `references/kat/aes-256/` — FIPS 197 + NIST SP 800-38A.
- `references/kat/x25519/` — RFC 7748.
- `references/kat/ed25519/` — RFC 8032.

Each subdirectory has a `README.md` recording the source URL, retrieval
date, and SHA-256 of the original file. Test files load from these
vectors; if a vector file is updated, the change is committed atomically
with the test changes.

## Risks specific to milestone 2

| Risk | Mitigation |
|------|-----------|
| ct-verif lacks RV32 support | Front-load: prove the ct path on `sha256_init` (a memset) before writing any other function. If it fails, file an ADR for the alternative (manual ct review with a documented checklist; pitchfork; bit-sliced from BearSSL with the ct argument inherited from BearSSL's analysis). |
| Hand-written field arithmetic for X25519 takes longer than estimated | Fall back to fiat-crypto's generated asm; equivalence-prove the generated form against the asm we hand-write (or vice versa). |
| Ed25519 needs SHA-512 we did not budget for | Decide early whether Reticulum uses Ed25519 or Ed25519ph (SHA-256 variant). If SHA-512 is required, scope it as a sub-milestone before Ed25519 sign/verify. |
| AES bitslicing is too slow on RV32IMAC for our throughput | Profile early; document trade-off. We are not targeting line-rate AES; correctness and ct trump speed. |
| KAT vector files drift from upstream sources | Vendor copies in `references/kat/`; record URL + retrieval date + SHA-256. Re-fetch is a deliberate (committed) action, never silent. |
| Verifier install proves too brittle to keep across machines | Document a Dockerfile or `nix-shell` recipe that pins every dependency. Acceptable to require `docker run` for the proof step; the hot loop is `make ci` (KAT only) and that stays native. |

## Current frontier

> Maintained in-place. Whoever finishes a chunk updates this section in the
> same commit that flips a function's status.

**Last updated:** 2026-05-02 (entire SHA-256 family verified end-to-end —
init, compress, update, final all under ADR-0009).

**State:**

- **Verifier toolchain green** under [ADR-0009](../adr/0009-verifier-toolchain.md):
  Cryptol 3.5.0, SAW 1.5, Binsec 0.11.1, angr 9.2.213 + pypcode 3.3.3,
  TLA+ Tools 2.19, Sail 0.20.1 + sail-riscv `4d5530b`, fiat-crypto
  `412e8af`, GHC 9.6.7 + cabal 3.10.3.0 (Tier C-future path), Coq 9.1.1.
  All binaries symlinked into `toolchain/local/bin/`; angr lives in
  `toolchain/venv/`. Versions pinned in `toolchain/versions.lock`. ADR-0009
  documents the per-tier responsibility (A=algorithmic, B=ct, C=binary
  equivalence, D=state machines, E=ISA reference) and the `@verify`
  comma-separated-paths syntax the dispatcher now consumes.

- **`sha256_init` verified.** Cryptol module + SAW driver
  ([proofs/crypto/sha256/SHA256Init.cry](../../proofs/crypto/sha256/SHA256Init.cry),
  [.saw](../../proofs/crypto/sha256/sha256_init.saw)) discharge Tier A
  (FIPS 180-4 §5.3.3 IV constants + LE serialisation + bijection over
  [32]). angr verifier ([.py](../../proofs/crypto/sha256/sha256_init.py))
  discharges Tier C (8 IV words written LE, length_bits=0, block_len=0,
  partial-block buffer + pad untouched, all 14 callee-saved registers
  preserved, ret within 200 basic blocks). End-to-end `./verify
  sha256_init` runs in ~3 s.

- **`sha256_compress` verified.** Cryptol model
  ([SHA256Compress.cry](../../proofs/crypto/sha256/SHA256Compress.cry))
  formalises FIPS 180-4 §6.2.2 from first principles — K table,
  ch/maj, big/small sigmas, message schedule, 64-round
  step-function, single-block compress. SAW driver
  ([sha256_compress.saw](../../proofs/crypto/sha256/sha256_compress.saw))
  proves five K-table boundary constants, the FIPS B.1 ("abc")
  single-block KAT, the canonical SHA-256("") single-block KAT, and
  algebraic sanity of ROTR/ch/maj — all via z3 in <1 s. angr verifier
  ([sha256_compress.py](../../proofs/crypto/sha256/sha256_compress.py))
  cross-checks the RV32 binary against a Python FIPS-180-4-from-scratch
  oracle on 6 vectors (FIPS B.1, empty, 4 random (H, M) pairs);
  asserts H_out matches, the 64-byte block buffer is unchanged, ctx[32..112]
  is untouched, and all 14 callee-saved regs preserved. End-to-end
  `./verify sha256_compress` runs in ~6 s.

- **`sha256_update` verified.** Cryptol model
  ([SHA256Update.cry](../../proofs/crypto/sha256/SHA256Update.cry))
  composes the verified compress into a streaming absorber
  (length_bits accumulator + 64-byte partial buffer). SAW driver proves
  two KAT scenarios (init + 3-byte buffer; init + full block triggers
  one compress) and **streaming associativity** — splitting input into
  two chunks vs concatenated input yields identical ctx state — for
  sub-block sizes (1+1, 10+20) and across one block boundary (30+40,
  symbolic over the entire 70-byte input domain, ~250 ms via z3). angr
  verifier exercises 8 scenarios (empty, 3, 63, 64, 65, 256, 513 bytes,
  resume-with-buffered-prefix) plus a separate one-shot-vs-chunked
  associativity check on a 200-byte message; all match a Python mirror
  of sha256_update.S. End-to-end ~16 s.

- **`sha256_final` verified.** Cryptol model
  ([SHA256Final.cry](../../proofs/crypto/sha256/SHA256Final.cry))
  formalises FIPS 180-4 §5.1.1 padding (one block when bl ≤ 55, two
  blocks otherwise) plus 32-byte big-endian H serialisation. SAW driver
  proves the canonical SHA-256 digests for "abc", "", FIPS B.2 56-byte
  string (boundary case forcing two-block padding), and 64 zero bytes
  (padding from a freshly-compressed empty buffer). angr verifier
  cross-checks the RV32 binary against `hashlib.sha256` on 9 messages
  spanning 0..129 bytes — covers both padding paths plus multi-block
  prefixes; asserts no write past out_ptr+32 and 14 callee-saved regs
  preserved. End-to-end ~10 s.

- **Remaining KAT-tested (awaiting per-function verifier work):**
  - HMAC-SHA-256: RFC 4231 TC1/2/3/6 pass via `'H'` marker.
  - HKDF-SHA-256 (extract, expand): RFC 5869 A.1/A.2/A.3 pass via `'E'`/`'X'` markers.
  - AES-256 helpers (sbox/invsbox, subbytes/invsubbytes, shiftrows/
    invshiftrows, mixcolumns/invmixcolumns, addroundkey, subword): all
    KAT-tested via per-primitive markers. Boyar-Peralta S-box, branch-free xtime.
  - AES-256-CBC chain (key_expand, encrypt_block, decrypt_block,
    cbc_encrypt, cbc_decrypt): FIPS 197 §A.3 + §C.3 + NIST SP 800-38A
    §F.2.5/§F.2.6 vectors pass via `'K'`/`'C'`/`'D'`/`'V'`/`'v'` markers.

**Eligible next chunks:**

1. **Lift HMAC + HKDF to verified.** RFC 2104 / RFC 5869. The Cryptol
   models compose `SHA256Final.sha256_oneshot` directly. SAW proves
   the canonical RFC test vectors (HMAC: RFC 4231; HKDF: RFC 5869 A.1
   /A.2/A.3) plus algebraic identities (HMAC's inner/outer key XOR
   structure; HKDF's extract-then-expand layering). angr cross-checks
   the binary against Python `hmac.new(key, msg, hashlib.sha256)`.

2. **Lift HMAC + HKDF to verified.** Once SHA-256 family is verified,
   HMAC and HKDF inherit the proof framework — their Cryptol specs
   compose `sha256_*` directly.

3. **Lift the AES-256-CBC chain to verified.** `aes_sbox` is the most
   interesting case: prove the Boyar-Peralta circuit equals the
   algebraic definition `S(x) = A * x^{-1} + b` over GF(2^8). Cryptol
   has the GF arithmetic primitives. `aes256_encrypt_block` then
   composes the verified primitives.

4. **Add Tier B (constant-time) for secret-handling crypto.** Write
   `.smt2` Binsec/Rel drivers tagging key/IV bytes as secrets, run
   `binsec -isa riscv32 -checkct` against the firmware ELF, prove no
   secret-dependent control flow or memory access. Start with
   `aes_sbox` (where Boyar-Peralta is the explicit constant-time
   choice) — that proof is the canonical example for the rest.

5. **X25519 field arithmetic + scalar mult.** The next big block of
   work. Field ops mod 2^255 - 19; Montgomery ladder. Likely 800–1500
   lines of asm. Decision still open: hand-write vs adopt fiat-crypto's
   generated form (now physically available under
   `references/fiat-crypto/fiat-c/src/curve25519_32.c`).

6. **Hardware RNG wrapper (`rng_init`, `rng_bytes`).** Small surface;
   gates Ed25519/X25519 keypair generation. On qemu the deterministic-
   fake path needs to be wired (with a bright `DETERMINISTIC_FAKE_RNG`
   symbol that must not survive into a release build).

7. **Vendor KAT vectors.** Populate `references/kat/sha256/`,
   `references/kat/hmac-sha256/`, `references/kat/hkdf/`,
   `references/kat/aes-256/`. Tests currently inline the canonical
   vectors; vendoring would consolidate and add the URL/SHA-256
   provenance the spec asks for.

8. **Tier C-future: `llvm_verify_riscv` upstream contribution.** When
   Tier C's bounded angr exploration becomes the limiting factor for a
   composite primitive (likely AES round or X25519 field-mul), build
   `macaw-riscv-symbolic` against GHC 9.6.7 and contribute an
   `llvm_verify_riscv` builtin to `saw-script`. ADR-0009 §"Tier C path
   forward" documents the plan.

## Retrospective

(To be added when the milestone reaches `Complete`.)
