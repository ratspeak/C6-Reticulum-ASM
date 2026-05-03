# Milestone 6: Link Establishment

- **Status:** Complete
- **Started:** 2026-05-03
- **Completed:** 2026-05-03
- **Estimate:** 6-8 weeks

## Goal

Establish encrypted point-to-point Reticulum links over the existing KISS
development interface. This milestone turns learned announce paths into a
minimal link handshake, derives symmetric session keys with the existing
X25519/HKDF primitives, and proves a single encrypted session packet can round
trip through the asm stack.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Link request builder/parser | [link_request_build](#link_request_build), [link_request_parse](#link_request_parse) | Forever |
| Link handshake state | [link_handshake_init](#link_handshake_init), [link_handshake_accept](#link_handshake_accept) | Forever |
| Link key derivation | [link_derive_keys](#link_derive_keys) | Forever |
| Session encryption/decryption | [link_session_encrypt](#link_session_encrypt), [link_session_decrypt](#link_session_decrypt) | Forever |
| Link packet dispatcher | [link_process_packet](#link_process_packet) | Development path through resource/channel milestone |
| Link state-machine proof | [verifier plan](#verifier-plan) | Forever |

## Definition of Done

- [x] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-6 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `link_request_build` and `link_request_parse` round-trip the milestone-6
      Reticulum link-request subset and reject malformed/truncated inputs
      without reading outside the caller-provided buffer.
- [x] `link_handshake_init` and `link_handshake_accept` maintain a bounded
      static link table with stable pending, established, duplicate, expired,
      and invalid statuses.
- [x] `link_derive_keys` derives deterministic session material from X25519
      shared secrets and transcript bytes using HKDF, with oracle tests against
      pyca/reference vectors.
- [x] `link_session_encrypt` and `link_session_decrypt` provide an AES-256-CBC
      plus HMAC authenticated payload path for one in-order session packet.
- [x] `link_process_packet` routes inbound link requests and encrypted link
      packets while preserving the milestone-5 announce RX path.
- [x] A TLA+ link state model covers request, accept, duplicate, reject,
      timeout, encrypted packet accept, and encrypted packet reject traces.
- [x] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`,
      `pytest --hardware tests/hardware/`, and `./verify <fn>` pass for every
      function added or modified in this milestone.

## Scope

Milestone 6 handles direct point-to-point links only. Resource transfer,
channels, retransmission, link persistence, ratchets, IFAC, and LoRa transport
are deferred. The link table is RAM-resident and fixed-capacity in this
milestone.

The milestone may implement a strict Reticulum subset first, but every accepted
packet must be traceable to the upstream link format. Any intentional subset
restriction must have a negative test and a verifier-state transition.

The first landed subset follows Reticulum 1.2.0 `RNS.Link`: HEADER_1
`LINKREQUEST` packets are unencrypted and carry
`x25519_public[32] || ed25519_link_signing_public[32] || signalling[3]`.
Milestone 6 currently accepts only the default `signalling_bytes(500,
AES-256-CBC) == 20 01 f4`; legacy no-signalling requests and alternate modes
are rejected with negative tests.

## Link State

State lives in `src/state/link.S`; constants live in `src/include/link.S`.

Planned fixed-capacity defaults:

```
LINK_TABLE_CAPACITY = 4
LINK_STATUS_PENDING = 1
LINK_STATUS_ESTABLISHED = 2
```

Each link entry stores at least:

| Field | Meaning |
|-------|---------|
| `valid` | Entry is populated |
| `status` | Pending or established |
| `last_seen_ms` | `clock_now_ms()` at update |
| `destination_hash` | Remote destination |
| `local_ephemeral_public` | Local X25519 ephemeral public key |
| `remote_ephemeral_public` | Remote X25519 ephemeral public key |
| `rx_key` / `tx_key` | Derived AES/HMAC material for this link subset |

Replacement and expiration rules are finalized in the first implementation
slice, before link packets can be accepted.

`link_handshake_init` implements the first table mutation path:
existing destination entries are refreshed in place, otherwise the first
invalid slot is used, otherwise the entry with the largest unsigned
`now_ms - last_seen_ms` age is evicted. New initiator entries store local
X25519 public/private bytes, local Ed25519 link-signing public/private bytes,
status `PENDING`, mode `AES-256-CBC`, and clear remote/key fields.

## link_request_build

Module: `link`.

Inputs:

```
a0 = destination_hash ptr (16 bytes)
a1 = local_x25519_public ptr (32 bytes)
a2 = local_ed25519_public ptr (32 bytes)
a3 = raw packet out ptr
a4 = raw packet capacity
```

Outputs:

```
a0 = raw packet length on success, negative errno on failure
```

Responsibilities:

1. Build the current upstream link-request subset using the existing HEADER_1
   packet conventions: flags `0x02`, hops `0`, destination hash, context `0`,
   X25519 public key, Ed25519 link-signing public key, and default signalling.
2. Reject null pointers and insufficient capacity.
3. Avoid heap allocation and keep all temporaries static or caller-provided.

## link_request_parse

Module: `link`.

Inputs:

```
a0 = raw packet ptr
a1 = raw packet len
a2 = link_request_t* out
```

Outputs:

```
a0 = 0 on success, negative errno on malformed input
```

Responsibilities:

1. Reject short, wrong-type, wrong-context, over-MDU, legacy no-signalling, or
   non-default mode/MTU packets.
2. Extract destination hash, remote X25519 public key, remote Ed25519
   link-signing public key, MTU, and mode into a bounded caller-provided struct.
3. Never read beyond `raw_packet[0:raw_len]`.

## link_handshake_init

Module: `link`.

Inputs:

```
a0 = destination_hash ptr (16 bytes)
a1 = raw packet out ptr
a2 = raw packet capacity
```

Outputs:

```
a0 = raw packet length on success, negative errno on failure
```

Responsibilities:

1. Allocate or update a pending link entry for the destination using the
   deterministic existing, first-invalid, oldest-age replacement rule.
2. Generate local X25519 and Ed25519 ephemeral key material.
3. Emit a link request packet using `link_request_build`.

## link_handshake_accept

Module: `link`.

Inputs:

```
a0 = link_request_t* parsed
```

Outputs:

```
a0 = 0 on established or positive duplicate status, negative errno on invalid
```

Responsibilities:

1. Validate parsed request shape.
2. Compute the upstream-compatible link request ID from the request hashable
   part without signalling bytes.
3. Generate local X25519 material, compute the shared secret, derive session
   material with `link_derive_keys`, and create or update a bounded
   established link entry.

## link_derive_keys

Module: `link`.

Inputs:

```
a0 = shared_secret ptr (32 bytes)
a1 = transcript ptr
a2 = transcript len
a3 = key_material_out ptr
```

Outputs:

```
a0 = 0 on success, negative errno on invalid input
```

Responsibilities:

1. Use HKDF-SHA-256 with the transcript/link-id bytes as salt and the X25519
   shared secret as input key material.
2. Produce 64 bytes of AES-256-CBC token material, matching upstream
   `RNS.Link` mode length.
3. Match Python `hmac`/`hashlib` reference vectors for deterministic inputs.

## link_session_encrypt

Module: `link`.

Inputs:

```
a0 = link entry ptr
a1 = plaintext ptr
a2 = plaintext len
a3 = ciphertext out ptr
a4 = ciphertext capacity
```

Outputs:

```
a0 = ciphertext length on success, negative errno on failure
```

Responsibilities:

1. Encrypt one in-order payload as the Reticulum Token AES-256-CBC subset:
   `IV[16] || AES-CBC(PKCS7(plaintext)) || HMAC-SHA256[32]`.
2. Use the first 32 derived bytes as the signing key and the second 32 bytes
   as the AES-256 key.
3. Reject overflow and invalid link state before emitting token material.

## link_session_decrypt

Module: `link`.

Inputs:

```
a0 = link entry ptr
a1 = ciphertext ptr
a2 = ciphertext len
a3 = plaintext out ptr
a4 = plaintext capacity
```

Outputs:

```
a0 = plaintext length on success, negative errno on invalid authentication,
     invalid state, or overflow
```

Responsibilities:

1. Verify HMAC before releasing plaintext.
2. Decrypt one in-order AES-256-CBC payload into bounded scratch, validate
   PKCS7 padding, then copy only the unpadded plaintext to the caller.
3. Reject tampered tag, IV, ciphertext, wrong-link inputs, invalid padding,
   and caller output overflow.

## link_process_packet

Module: `link`.

Inputs:

```
a0 = raw packet ptr
a1 = raw packet len
a2 = interface_id
```

Outputs:

```
a0 = stable status code for accepted, duplicate, invalid, and encrypted packet
```

Responsibilities:

1. Dispatch HEADER_1 link requests to `link_request_parse` and
   `link_handshake_accept`.
2. Dispatch HEADER_1 DATA packets addressed to a known established link ID to
   `link_session_decrypt`, leaving plaintext in bounded session scratch for the
   later resource/channel milestone.
3. Preserve milestone-5 announce RX behavior by passing announce packets to
   `transport_process_announce`.

## Verifier Plan

- TLA+ state model [proofs/link/link_state.tla](../../proofs/link/link_state.tla)
  for pending, established, duplicate, timeout, reject, and encrypted-packet
  transitions.
- Bounds proof for `link_request_parse`.
- KAT/oracle coverage for key derivation and session encryption/decryption.
- Source-shape proofs that authentication checks precede plaintext release.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| Upstream link packet details are broader than this first subset | Start with a documented strict subset, then expand only with tests and verifier states. |
| Session encryption could expose plaintext before authentication | Decrypt path must have a source-shape proof that HMAC verification gates plaintext copy. |
| Link table semantics may conflict with resource/channel needs | Keep replacement deterministic and document all statuses before resource transfer starts. |
| C6 Ed25519/X25519 cost may make link setup slow | Measure with hardware tests; correctness remains the milestone gate. |

## Retrospective

Milestone 6 completed as a strict Reticulum subset: current HEADER_1 link
requests with MTU signalling, bounded RAM link table state, X25519/HKDF
session key derivation, Reticulum Token-compatible AES-256-CBC session
encryption, and a dispatcher for link requests, established encrypted packets,
and existing announce RX traffic. The largest deliberate subset is encrypted
DATA context handling: milestone 6 proves one in-order context-0 encrypted
packet, while resource and channel contexts move to milestone 7.

The link table is intentionally small (`4` entries) and RAM-only. Replacement
uses the same existing/first-invalid/oldest-age rule established for transport
paths, which kept the state machine finite enough for direct QEMU tests and the
TLA+ model. Accept-side link proof/signature packets are still deferred; the
milestone proves shared-key establishment and encrypted payload handling, not
full peer identity proof exchange.

Final gates on 2026-05-03:

- `./verify --module link` passed for all eight milestone-6 link functions.
- `make ci` passed with `649 passed, 14 skipped`.
- `make build TARGET=qemu-virt` and `make build TARGET=c6` passed.
- `pytest --hardware tests/hardware/ -q -p no:cacheprovider` passed with
  `14 passed`.
- Stack maximum remained `2304 / 16384` bytes.
- `git diff --check` passed.
