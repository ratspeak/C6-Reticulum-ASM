# Milestone 3: Identity + announce TX

- **Status:** Active
- **Started:** 2026-05-03
- **Estimate:** 3-4 weeks

## Goal

Create a local Reticulum identity in static memory and emit a valid signed
Reticulum announce packet over the existing KISS serial development interface.
This milestone is the first point where the crypto stack becomes protocol state:
X25519 and Ed25519 keypairs are combined into the Reticulum identity layout,
destination hashes are derived exactly as upstream Reticulum derives them, and
the outgoing announce wire image validates under the Python reference.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Identity memory layout | [identity state](#identity-state) | Forever |
| Identity keypair creation | [identity_create](#identity_create) | Forever |
| Identity hash derivation | [identity_hash](#identity_hash) | Forever |
| Destination hash helpers | [destination hashes](#destination-hashes) | Forever |
| Announce packet builder | [announce_build](#announce_build) | Forever |
| KISS announce TX path | [announce_send](#announce_send) | Development path through milestone 7; reused by LoRa tests |
| Announce state-machine proof | [verifier plan](#verifier-plan) | Forever |

## Definition of done

- [ ] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-3 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `identity_create` produces an identity whose private bytes are
      `x25519_sk || ed25519_seed`, whose public bytes are
      `x25519_pk || ed25519_pk`, and whose hash is
      `SHA256(public_bytes)[0:16]`, matching
      `upstream/Reticulum/RNS/Identity.py`.
- [x] `destination_name_hash` and `destination_hash` match
      `upstream/Reticulum/RNS/Destination.py` for at least
      `rnstransport.nodes`, `lxmf.delivery`, and one harness-local test name.
- [ ] `announce_build` emits a HEADER_1 announce with flags `0x01`, hops `0`,
      context `0x00`, destination hash bytes, and announce payload
      `public_key || name_hash || random_hash || signature || app_data`.
- [ ] The signature verifies with upstream `RNS.Identity.validate_announce()`
      for app-data-empty and app-data-present announces.
- [ ] `announce_send` KISS-frames the raw announce packet and writes it through
      the existing `uart_tx_bytes` path under qemu-virt.
- [ ] The TLA+ announce-TX state machine accepts every harness trace emitted by
      the asm path: `identity.ready` -> `announce.built` -> `kiss.tx_frame`.
- [ ] `make ci`, `make build TARGET=qemu-virt`, and `./verify <fn>` pass for
      every function added or modified in this milestone.

## Wire Format

This milestone implements non-ratchet announces only. Ratchet announces are
deferred until link/ratchet state exists.

The local identity public key is 64 bytes:

```
x25519_public[32] || ed25519_public[32]
```

The local identity private key is 64 bytes:

```
x25519_private[32] || ed25519_seed[32]
```

The identity hash is:

```
identity_hash = SHA256(public_key)[0:16]
```

For a destination name, the name hash is:

```
name_hash = SHA256(destination_name_utf8_without_identity_suffix)[0:10]
```

The destination hash is:

```
destination_hash = SHA256(name_hash || identity_hash)[0:16]
```

The unsigned announce payload is:

```
public_key[64] || name_hash[10] || random_hash[10] || app_data
```

The signed data is:

```
destination_hash[16] || public_key[64] || name_hash[10] ||
random_hash[10] || app_data
```

The announce payload is:

```
public_key[64] || name_hash[10] || random_hash[10] ||
signature[64] || app_data
```

The Reticulum packet around the payload is a HEADER_1 announce:

| Byte range | Value |
|------------|-------|
| 0 | `0x01` (`HEADER_1`, context flag unset, broadcast, SINGLE destination, ANNOUNCE) |
| 1 | `0x00` hops |
| 2..17 | destination hash |
| 18 | `0x00` context (`Packet.NONE`) |
| 19..end | announce payload |

`random_hash` is opaque to announce validation in upstream Reticulum. For this
milestone it is generated as 10 bytes from `rng_bytes`; a later wall-clock
milestone may switch the last five bytes to a timestamp-compatible encoding if
that becomes useful for replay analysis.

## Identity State

State lives in `src/state/identity.S`; constants live in
`src/include/identity.S`.

```
IDENTITY_OFF_X25519_SK        0   // 32 bytes
IDENTITY_OFF_ED25519_SK      32   // 32 bytes seed
IDENTITY_OFF_X25519_PK       64   // 32 bytes
IDENTITY_OFF_ED25519_PK      96   // 32 bytes
IDENTITY_OFF_HASH           128   // 16 bytes
IDENTITY_T_SIZE             160   // 16-byte aligned
```

The canonical private-key byte range is `[0, 64)`. The canonical public-key
byte range is `[64, 128)`. These ranges intentionally match upstream
`Identity.get_private_key()` and `Identity.get_public_key()` byte order:
`x25519 || ed25519`. The 16 bytes at `[144, 160)` are reserved and zeroed by
`identity_create`.

## identity_create

Module: `identity`.

Inputs:

```
a0 = identity_t* out
```

Outputs:

```
a0 = 0 on success, negative errno on failure
identity_t filled
```

Responsibilities:

1. Call `x25519_keypair(pk_out=out+64, sk_out=out+0)`.
2. Call `ed25519_keypair(sk_out=out+32, pk_out=out+96)`.
3. Call `identity_hash(public_key_ptr=out+64, hash_out=out+128)`.
4. Zero reserved bytes `[144, 160)`.

Verification:

- QEMU KAT against the deterministic RNG oracle and pyca/cryptography for both
  generated keypairs.
- Layout check against upstream `Identity.get_private_key()`,
  `Identity.get_public_key()`, and `Identity.truncated_hash()`.
- Constant-time obligation inherited from keypair primitives; no logging while
  private-key bytes are live.

## identity_hash

Module: `identity`.

Inputs:

```
a0 = public_key ptr (64 bytes)
a1 = hash_out ptr (16 bytes)
```

Outputs:

```
hash_out = SHA256(public_key)[0:16]
```

Verification:

- Cryptol/SAW wrapper over SHA-256 truncation.
- QEMU pytest vectors against `hashlib.sha256(public_key).digest()[:16]`.

## Destination Hashes

### destination_name_hash

Module: `destination`.

Inputs:

```
a0 = UTF-8 destination-name ptr
a1 = destination-name length
a2 = name_hash_out ptr (10 bytes)
```

Outputs:

```
name_hash_out = SHA256(name_bytes)[0:10]
```

The caller supplies the Reticulum name without the identity hash suffix, matching
`Destination.expand_name(None, app_name, *aspects)`.

### destination_hash

Module: `destination`.

Inputs:

```
a0 = name_hash ptr (10 bytes)
a1 = identity_hash ptr (16 bytes)
a2 = destination_hash_out ptr (16 bytes)
```

Outputs:

```
destination_hash_out = SHA256(name_hash || identity_hash)[0:16]
```

Verification:

- Direct vectors against `upstream/Reticulum/RNS/Destination.py`.
- Boundary tests for zero-length and maximum harness-supported name lengths on
  `destination_name_hash`; zero-length is legal at the hash layer even though
  higher-level destination construction rejects empty application names.

## announce_build

Module: `announce`.

Inputs:

```
a0 = identity_t*
a1 = name_hash ptr (10 bytes)
a2 = app_data ptr (may be 0 when app_data_len = 0)
a3 = app_data_len
a4 = raw_packet_out ptr
a5 = raw_packet_capacity
```

Outputs:

```
a0 = raw packet length on success, negative errno on overflow or invalid input
raw_packet_out = Reticulum HEADER_1 announce packet
```

Responsibilities:

1. Compute `destination_hash(name_hash, identity.hash)`.
2. Draw `random_hash[10]` with `rng_bytes`.
3. Assemble signed data in static announce scratch:
   `destination_hash || public_key || name_hash || random_hash || app_data`.
4. Sign with `ed25519_sign(sig_out, signed_data, signed_len, ed25519_seed)`.
5. Assemble the HEADER_1 raw packet described in [wire format](#wire-format).
6. Return overflow if `raw_packet_capacity < 19 + 64 + 10 + 10 + 64 + app_data_len`.

`app_data_len` is capped by the configured Reticulum MDU. No heap allocation is
permitted; large temporary buffers live in `src/state/announce.S`.

Verification:

- Python oracle builds the same announce using pyca/cryptography and upstream
  Reticulum constants, then verifies the asm packet with
  `RNS.Identity.validate_announce()`.
- Tests cover empty app data, non-empty app data, exact-capacity output, and
  one-byte-short overflow.
- TLA+ trace proof records build-state transitions and rejects `sent` without
  a successful `built`.

## announce_send

Module: `announce`.

Inputs:

```
a0 = identity_t*
a1 = name_hash ptr (10 bytes)
a2 = app_data ptr
a3 = app_data_len
```

Outputs:

```
a0 = raw announce length on success, negative errno on failure
```

Responsibilities:

1. Call `announce_build` into the static raw-announce TX buffer.
2. Call `kiss_encode_frame`.
3. Call `uart_tx_bytes` with the KISS frame.
4. Emit structured log events:
   - `announce\tbuilt\tlen=<raw_len>`
   - `kiss\ttx_frame\tlen=<kiss_len>`

The qemu-virt harness triggers this path through an `_main` dispatcher command
after `announce_build` is verified. The full demo trace begins with the
`identity\tready` event emitted by `identity_create`. Agent 1 owns the `_main`
integration edit because `_main` is a coordinator-owned conflict point.

## Verifier Plan

Artifacts:

- `proofs/identity/IdentityHash.cry`
- `proofs/identity/identity_hash.saw`
- `proofs/identity/IdentityCreate.cry`
- `proofs/identity/identity_create.saw`
- `proofs/destination/DestinationHash.cry`
- `proofs/destination/destination_name_hash.saw`
- `proofs/destination/destination_hash.saw`
- `proofs/announce/announce_tx.tla`
- QEMU pytest verifiers under `tests/identity/`, `tests/destination/`, and
  `tests/announce/`.

Tier mapping:

| Function | Tier obligation |
|----------|-----------------|
| `identity_hash` | Tier A truncation proof + QEMU KAT |
| `identity_create` | QEMU KAT + layout proof; CT by composition through keypair primitives |
| `destination_name_hash` | Tier A truncation proof + upstream vector tests |
| `destination_hash` | Tier A truncation proof + upstream vector tests |
| `announce_build` | QEMU/upstream oracle + TLA+ state transition trace |
| `announce_send` | QEMU KISS-frame integration + TLA+ trace |

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| Upstream Reticulum announce construction has implicit runtime assumptions | Use `upstream/Reticulum/RNS/Identity.py`, `Destination.py`, and `Packet.py` as the oracle for every byte, not memory or notes. |
| Announce signing requires large static scratch | Put scratch in `src/state/announce.S`, size it from `src/include/config.S`, and fail the build if it threatens stack/RAM budget. |
| `_main` dispatcher edits conflict with production work | Agent 1 owns `_main`; production agents queue the integration request after `announce_build` verifies. |
| Random hash timestamp parity is ambiguous without wall clock | Treat `random_hash` as opaque 10-byte nonce for milestone 3; upstream validation only signs and verifies the bytes. |

## Current Frontier

Milestone 3 opened 2026-05-03 after milestone 2 closed without creating this
spec. Eligible first claims:

1. `identity_hash` — smallest standalone function; unblocks identity layout.
2. `destination_name_hash` and `destination_hash` — pure SHA-256 truncation
   helpers with straightforward upstream vectors.
3. `identity_create` — keypair composition and layout, after `identity_hash`.

Do not claim `announce_build` until the identity and destination hash helpers
are verified.
