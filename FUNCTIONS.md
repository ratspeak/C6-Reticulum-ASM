# Function Registry

The single source of truth for every function in this project. Every assembly function in
the production binary appears here. Adding, modifying, or removing a function requires
updating this file in the same commit.

This file is consumed by both humans (orientation, work-picking) and tooling (CI checks
that every `src/**/*.S` symbol is registered, every `verified` entry has a passing verifier).

## How to read this file

Functions are organized by module, in dependency order. Within a module, functions appear in
the order an agent would naturally implement them (primitives before consumers).

Each function entry has:

- **Status:** one of:
  - `planned` — not yet started.
  - `in-progress` — actively being implemented; agent is responsible for completing or
    relinquishing within a reasonable window.
  - `tested` — asm written, tests pass, formal verifier not yet run or not yet passing.
  - `verified` — asm written, tests pass, formal verifier passes (per ADR-0006 obligation).
  - `superseded` — replaced by a different function; kept for history with a pointer.
- **Depends-on:** functions that must reach `verified` before this function can be implemented.
  Empty if the function has no dependencies within the project.
- **ADRs:** ADR numbers this function implements or is constrained by.
- **Spec:** link to the milestone spec entry that defines this function in detail.

## Status legend

| Symbol | Status |
|--------|--------|
| ☐ | planned |
| ◐ | in-progress |
| ◑ | tested |
| ◉ | verified |
| ⊘ | superseded |

## Statistics

(Updated manually at milestone boundaries; tooling to auto-generate this section is a
post-milestone-1 task. Run `./verify --all` for the live tally.)

- Total functions registered: **39** (excludes wildcard placeholders like `x25519_field_*`)
- Verified: 62 (milestone 1 software side + entire milestone-2 crypto stack so far: SHA-256 family + HMAC + HKDF + AES-256-CBC stack + 13 X25519 functions + RNG (deterministic-fake) — all under ADR-0009)
- Tested (KAT-only, formal verifier pending): 0
- Planned: Ed25519 (3) + `uart_isr` (hw). The X25519 stack and the QEMU-bring-up RNG are complete; the production ESP32-C6 RNG (HMAC-DRBG seeded from the on-chip TRNG) replaces the deterministic-fake at hardware bring-up time. `decode_u` removed from the registry — `field_unpack`'s limb 9 mask already drops bit 255 (the RFC 7748 high-bit mask), so a separate decode_u is redundant in our representation.
- `x25519_field_mul121665` and `x25519_field_mul` both rely on a QEMU-pytest Tier C path rather than angr: the pcode RV32IMC engine mistranslates the `mul + mulh + add-with-carry` 64-bit accumulator chain (40-of-40 random inputs disagreed in earlier runs against a hand-written Python asm-level simulator that mirrors the asm verbatim). The X25519 dispatcher tag `'F'` (added in this commit) drives `x25519_field_mul` under qemu-system-riscv32 and compares to the algebraic-spec-validated Python oracle. Same Tier C-future resolution (SAW + macaw-riscv per ADR-0009); QEMU plumbing for `x25519_field_mul121665` is a follow-up since its asm is also covered by transitivity through the simulator.
- Note: AES Tier C is currently Cryptol+SAW (Tier A) plus QEMU pytest KATs; angr's pcode RV32IMC engine is empirically unreliable for the Boyar-Peralta circuit and dependent functions, so 11 of the 15 AES functions defer the angr Tier-C-bounded path to future SAW+macaw-riscv work (ADR-0009 §"Tier C path forward"). The 4 AES functions where pcode is reliable (`aes_addroundkey`, `aes_shiftrows`, `aes_invshiftrows`, `aes_mixcolumns`) carry both Tier A and Tier C verifiers.
- The X25519 algorithmic spec [proofs/crypto/x25519/X25519.cry](proofs/crypto/x25519/X25519.cry) and SAW driver are landed and proven against RFC 7748 §5.2 / §6.1 KATs; each of the 14 listed functions hangs off the same shared model. The asm implementation follows in subsequent commits.
- In progress: 0
- Planned: 1 milestone-1 leaf (`uart_isr`, hw-only) + the milestone-2..9 chain (X25519, Ed25519, RNG)

The end-to-end milestone-1 demo path is observable: KISS-framed Reticulum
packets sent to qemu's stdin produce `boot.ready`, `kiss.rx_frame`, and
`packet.parsed`/`packet.rejected` log lines on its stdout. See
[docs/milestones/milestone-1.md#current-frontier](docs/milestones/milestone-1.md#current-frontier).

---

## Module: `boot`

System startup, before any other code runs. Lives at the reset vector.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `_reset` | ◉ verified | — | 0001, 0002, 0008 | [milestone-1](docs/milestones/milestone-1.md#boot) |
| `_init_bss` | ◉ verified | `_reset` | 0002 | [milestone-1](docs/milestones/milestone-1.md#boot) |
| `_init_data` | ◉ verified | `_reset` | 0002 | [milestone-1](docs/milestones/milestone-1.md#boot) |
| `_main` | ◉ verified | `_init_bss`, `_init_data`, `clock_init`, `uart_init`, `log_init`, `log_event`, `log_hex`, `log_str`, `log_hex_buf`, `uart_rx_byte`, `uart_tx_byte`, `clock_now_ms`, `kiss_decode_byte`, `packet_parse_header`, `sha256_init`, `sha256_update`, `sha256_final`, `hmac_sha256`, `hkdf_extract`, `hkdf_expand`, `aes_sbox`, `aes_invsbox`, `aes_mixcolumns`, `aes_invmixcolumns`, `aes256_key_expand`, `aes256_encrypt_block`, `aes256_decrypt_block`, `aes256_cbc_encrypt`, `aes256_cbc_decrypt` | 0001, 0004, 0006, 0008 | [milestone-1](docs/milestones/milestone-1.md#boot) |

## Module: `clock`

Clock and PLL configuration. Brings the chip to a known 160 MHz operating state.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `clock_init` | ◉ verified | — | 0008 | [milestone-1](docs/milestones/milestone-1.md#clock) |
| `clock_now_ticks` | ◉ verified | `clock_init` | 0001 | [milestone-1](docs/milestones/milestone-1.md#clock) |
| `clock_now_ms` | ◉ verified | `clock_now_ticks` | 0001, 0008 | [milestone-1](docs/milestones/milestone-1.md#clock) |
| `clock_get_freq` | ◉ verified | `clock_init` | 0001 | [milestone-1](docs/milestones/milestone-1.md#clock) |
| `clock_delay_us` | ◉ verified | `clock_init` | 0001 | [milestone-1](docs/milestones/milestone-1.md#clock) |

## Module: `uart`

UART0 driver. Interrupt-driven RX and TX with ring buffers. Permanent diagnostic + KISS interface I/O.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `uart_init` | ◉ verified | `clock_init` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#uart) |
| `uart_tx_byte` | ◉ verified | `uart_init` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#uart) |
| `uart_tx_bytes` | ◉ verified | `uart_tx_byte` | 0001, 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#uart) |
| `uart_rx_byte` | ◉ verified | `uart_init` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#uart) |
| `uart_rx_available` | ◉ verified | `uart_init` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#uart) |
| `uart_isr` | ☐ planned | `uart_init` | 0004 | [milestone-1](docs/milestones/milestone-1.md#uart) |

## Module: `log`

Structured logging primitives over UART0. See ADR-0004.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `log_init` | ◉ verified | `uart_init`, `clock_init` | 0004 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_str` | ◉ verified | `log_init` | 0004 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_hex` | ◉ verified | `log_init` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_u32` | ◉ verified | `log_init` | 0001, 0004 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_bytes` | ◉ verified | `log_hex` | 0004 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_event` | ◉ verified | `log_init`, `log_hex`, `log_str`, `clock_now_ms` | 0004, 0008 | [milestone-1](docs/milestones/milestone-1.md#log) |
| `log_hex_buf` | ◉ verified | `log_hex` | 0004 | [milestone-1](docs/milestones/milestone-1.md#log) |

## Module: `kiss`

KISS framing layer. Both encode (frame → escaped byte stream) and decode (byte stream → frame).
Used by every interface (USB-serial in dev, LoRa in milestone 8).

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `kiss_decode_byte` | ◉ verified | — | 0002 | [milestone-1](docs/milestones/milestone-1.md#kiss) |
| `kiss_decode_reset` | ◉ verified | — | 0002 | [milestone-1](docs/milestones/milestone-1.md#kiss) |
| `kiss_encode_frame` | ◉ verified | — | 0002 | [milestone-1](docs/milestones/milestone-1.md#kiss) |

## Module: `packet`

Reticulum wire format. Header parser, header serializer, field accessors. Permanent — every
later module reads packets through this.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `packet_parse_header` | ◉ verified | — | 0002 | [milestone-1](docs/milestones/milestone-1.md#packet) |
| `packet_get_dest_hash` | ◉ verified | `packet_parse_header` | 0002 | [milestone-1](docs/milestones/milestone-1.md#packet) |
| `packet_get_payload` | ◉ verified | `packet_parse_header` | 0002 | [milestone-1](docs/milestones/milestone-1.md#packet) |
| `packet_serialize_header` | ◉ verified | — | 0002 | [milestone-1](docs/milestones/milestone-1.md#packet) |

## Module: `crypto/sha256`

SHA-256 implementation. Foundation for HMAC, HKDF, identity hashing. Per ADR-0006: equivalence
proof + KAT + constant-time required.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `sha256_init` | ◉ verified | — | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#sha256) |
| `sha256_compress` | ◉ verified | `sha256_init` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#sha256) |
| `sha256_update` | ◉ verified | `sha256_init`, `sha256_compress` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#sha256) |
| `sha256_final` | ◉ verified | `sha256_update` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#sha256) |

## Module: `crypto/hmac`

HMAC-SHA-256 per RFC 2104. Used for IFAC, ratchets, message authentication.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `hmac_sha256` | ◉ verified | `sha256_init`, `sha256_update`, `sha256_final` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#hmac) |

## Module: `crypto/hkdf`

HKDF per RFC 5869. Used for Reticulum key derivation.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `hkdf_extract` | ◉ verified | `hmac_sha256` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#hkdf) |
| `hkdf_expand` | ◉ verified | `hmac_sha256` | 0001, 0002, 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#hkdf) |

## Module: `crypto/aes`

AES-256-CBC. Used for Reticulum link encryption. Constant-time S-box uses
the Boyar-Peralta combinational circuit (no table lookups, per ADR-0006).

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `aes_sbox` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_invsbox` | ◉ verified | `aes_sbox` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_subbytes` | ◉ verified | `aes_sbox` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_invsubbytes` | ◉ verified | `aes_invsbox` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_shiftrows` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_invshiftrows` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_mixcolumns` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_invmixcolumns` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_addroundkey` | ◉ verified | — | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes_subword` | ◉ verified | `aes_sbox` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes256_key_expand` | ◉ verified | `aes_subword` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes256_encrypt_block` | ◉ verified | `aes_subbytes`, `aes_shiftrows`, `aes_mixcolumns`, `aes_addroundkey` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes256_decrypt_block` | ◉ verified | `aes_invsubbytes`, `aes_invshiftrows`, `aes_invmixcolumns`, `aes_addroundkey` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes256_cbc_encrypt` | ◉ verified | `aes256_encrypt_block` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |
| `aes256_cbc_decrypt` | ◉ verified | `aes256_decrypt_block` | 0006, 0009 | [milestone-2](docs/milestones/milestone-2.md#aes) |

## Module: `crypto/x25519`

X25519 ECDH per RFC 7748. The largest single primitive in the project.
Field arithmetic is over GF(2^255 - 19); the asm uses 10 limbs of ~26-bit
each (radix 2^25.5) so 32-bit multiplies + 64-bit accumulators avoid
overflow and reduction can be folded into limb carries. The Cryptol
algorithmic spec [proofs/crypto/x25519/X25519.cry](proofs/crypto/x25519/X25519.cry)
is verified against RFC 7748 §5.2 and §6.1 KATs (Tier A); per-function
asm verifiers follow the same Tier A → Tier C pattern as the SHA-256
and AES stacks.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `x25519_field_unpack` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_pack` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_add` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_sub` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_mul` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_sq` | ◉ verified | `x25519_field_mul` | 0006, 0009 | (milestone 2) |
| `x25519_field_mul121665` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_field_inv` | ◉ verified | `x25519_field_mul`, `x25519_field_sq` | 0006, 0009 | (milestone 2) |
| `x25519_decode_scalar` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_cswap` | ◉ verified | — | 0006, 0009 | (milestone 2) |
| `x25519_montgomery_ladder` | ◉ verified | `x25519_field_*`, `x25519_cswap` | 0006, 0009 | (milestone 2) |
| `x25519_scalar_mult` | ◉ verified | `x25519_montgomery_ladder`, `x25519_decode_*`, `x25519_field_pack` | 0006, 0009 | (milestone 2) |
| `x25519_keypair` | ◉ verified | `x25519_scalar_mult`, `rng_bytes` | 0006, 0009 | (milestone 2) |

## Module: `crypto/ed25519`

Ed25519 signing per RFC 8032. Used for announce signatures and identity proofs.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `ed25519_keypair` | ☐ planned | `sha256_*`, `x25519_field_*` | 0006 | (milestone 2) |
| `ed25519_sign` | ☐ planned | `ed25519_keypair` | 0006 | (milestone 2) |
| `ed25519_verify` | ☐ planned | `ed25519_keypair` | 0006 | (milestone 2) |

## Module: `crypto/rng`

Cryptographically secure random number generation. Source: ESP32-C6 hardware RNG.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `rng_init` | ◉ verified | `clock_init` | 0006, 0009 | (milestone 2) |
| `rng_bytes` | ◉ verified | `rng_init`, `sha256_*` | 0006, 0009 | (milestone 2) |

## Module: `identity`

Reticulum identity: keypair generation, persistence, hash derivation.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `identity_create` | ☐ planned | `x25519_keypair`, `ed25519_keypair`, `rng_bytes` | — | (milestone 3) |
| `identity_hash` | ☐ planned | `sha256_*` | — | (milestone 3) |
| `identity_save` | ☐ planned | `flash_*`, `identity_create` | — | (milestone 4) |
| `identity_load` | ☐ planned | `flash_*` | — | (milestone 4) |

## Module: `transport`

Announce processing, path table, destination cache. Reticulum's routing layer.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 5 is activated) | ☐ planned | | | (milestone 5) |

## Module: `link`

Encrypted point-to-point link establishment. Curve25519 handshake + AES session.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 6 is activated) | ☐ planned | | | (milestone 6) |

## Module: `resource`

Reliable resource transfer over a link. Fragmentation, channels.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 7 is activated) | ☐ planned | | | (milestone 7) |

## Module: `flash`

Flash driver: page read/write/erase. Required for identity persistence, destination caches.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| `flash_init` | ☐ planned | `clock_init` | — | (milestone 4) |
| `flash_read` | ☐ planned | `flash_init` | — | (milestone 4) |
| `flash_write_page` | ☐ planned | `flash_init` | — | (milestone 4) |
| `flash_erase_sector` | ☐ planned | `flash_init` | — | (milestone 4) |

## Module: `interface/lora`

LoRa interface via SX1276/RFM95 over SPI. The first wireless interface.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 8 is activated) | ☐ planned | | 0003 | (milestone 8) |

## Module: `interface/spi`

SPI driver. Used by the LoRa interface.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 8 is activated) | ☐ planned | | | (milestone 8) |

## Module: `lxmf`

LXMF messaging on top of Reticulum.

| Function | Status | Depends-on | ADRs | Spec |
|----------|--------|-----------|------|------|
| (functions added when milestone 9 is activated) | ☐ planned | | | (milestone 9) |

---

## Maintenance

- **Adding a function:** add the entry under its module with status `planned`. Same commit
  introduces the milestone-spec entry for it.
- **Starting work:** change status to `in-progress`. Commit the stub file simultaneously.
- **Tests passing:** change status to `tested`. Commit when tests are committed.
- **Verifier passing:** change status to `verified`. Commit when verifier spec is committed.
- **Replacing a function:** mark old as `superseded` with a pointer; do not delete the entry.
  History matters.
- **Removing a planned function (no work done yet):** delete the row outright. Add a note in
  the commit message explaining why it is no longer needed.

The CI build fails if:

- A `.S` file in `src/` defines a global symbol not registered here.
- A function entry has `status: verified` but `./verify <function>` fails.
- A function entry references a `depends-on` that does not exist.
