# Milestone 5: Transport RX

- **Status:** Complete
- **Started:** 2026-05-03
- **Completed:** 2026-05-03
- **Estimate:** 4-6 weeks

## Goal

Accept inbound Reticulum announces over the existing KISS development
interface, validate their signatures, and maintain a bounded in-RAM transport
path table. This is the first receive-side routing milestone: the node learns
peer destinations from announces without establishing links or forwarding
traffic yet.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Inbound announce parser | [announce_parse](#announce_parse) | Forever |
| Inbound announce validator | [announce_validate](#announce_validate) | Forever |
| Transport path table | [path table](#path-table) | Forever |
| Announce-to-path processor | [transport_process_announce](#transport_process_announce) | Forever |
| Main-loop RX integration | [boot integration](#boot-integration) | Development path through LoRa milestone |
| Transport state-machine proof | [verifier plan](#verifier-plan) | Forever |

## Definition of Done

- [x] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-5 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `announce_parse` accepts well-formed non-ratchet HEADER_1 announces and
      rejects malformed flags, hops/context shape, short payloads, over-MDU
      packets, and truncated signatures without copying out of bounds.
- [x] `announce_validate` recomputes `identity_hash`, destination hash, and
      Ed25519 signature validity for inbound announces, with negative tests for
      tampered destination hash, public key, name hash, random hash, signature,
      and app data.
- [x] `transport_path_init`, `transport_path_update`, and
      `transport_path_lookup` maintain a fixed-capacity path table with
      deterministic replacement and no heap allocation.
- [x] `transport_process_announce` validates a parsed announce, updates or
      creates the path-table entry keyed by destination hash, and returns a
      stable status code for accepted, duplicate, invalid, and full-table
      cases.
- [x] `_main` routes inbound Reticulum announce packets through
      `transport_process_announce` while preserving existing packet parser logs
      and the milestone-3 local `N` announce command.
- [x] A TLA+ transport state model accepts every observable asm trace for
      accept, reject, update, duplicate, and eviction cases.
- [x] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`,
      `pytest --hardware tests/hardware/`, and `./verify <fn>` pass for every
      function added or modified in this milestone.

## Scope

Milestone 5 handles non-ratchet announces only. Link requests, encrypted
traffic, ratchets, retransmission, LoRa interfaces, and path persistence are
deferred. The path table is RAM-resident in this milestone; flash persistence
for destination/path caches waits until the update and eviction semantics are
stable.

The inbound wire format is the same HEADER_1 announce described in
[milestone-3](milestone-3.md#wire-format):

```
flags[1] || hops[1] || destination_hash[16] || context[1] ||
public_key[64] || name_hash[10] || random_hash[10] ||
signature[64] || app_data[*]
```

The signed data is:

```
destination_hash || public_key || name_hash || random_hash || app_data
```

## Announce RX State

State lives in `src/state/announce.S` and `src/state/transport.S`; constants
live in `src/include/announce.S` and `src/include/transport.S`.

The parser writes a bounded `announce_rx_t` view into static storage or a
caller-provided output struct:

| Field | Size | Meaning |
|-------|------|---------|
| `raw_len` | 4 | Full raw packet length |
| `payload_len` | 4 | Payload length after byte 18 context |
| `app_data_len` | 4 | Payload bytes after the signature |
| `destination_hash` | 16 | Packet destination hash |
| `public_key` | 64 | Announcing identity public key |
| `name_hash` | 10 | Destination name hash |
| `random_hash` | 10 | Announce random hash |
| `signature` | 64 | Ed25519 signature |
| `app_data_ptr` | 4 | Pointer into the original packet buffer |

The parser may copy fixed fields into the struct but must not copy app data.
App data remains a `(ptr, len)` view into the already bounded KISS buffer.

## Path Table

Milestone 5 uses a fixed-capacity RAM table:

```
TRANSPORT_PATH_CAPACITY = 8
TRANSPORT_INTERFACE_KISS = 1
```

Each path entry stores:

| Field | Size | Meaning |
|-------|------|---------|
| `valid` | 1 | Entry is populated |
| `interface_id` | 1 | `TRANSPORT_INTERFACE_KISS` for this milestone |
| `hops` | 1 | Packet hop count observed on receive |
| `reserved` | 1 | Zero |
| `last_seen_ms` | 4 | `clock_now_ms()` at update |
| `destination_hash` | 16 | Lookup key |
| `identity_hash` | 16 | `SHA256(public_key)[0:16]` |
| `public_key` | 64 | Announcing identity public key |

Replacement is deterministic: update an existing destination hash first; else
use the first invalid entry; else replace the entry with the oldest
`last_seen_ms` using unsigned 32-bit age comparison.

## announce_parse

Module: `announce`.

Inputs:

```
a0 = raw packet ptr
a1 = raw packet len
a2 = announce_rx_t* out
```

Outputs:

```
a0 = 0 on success, negative errno on failure
out = parsed fixed fields on success
```

Responsibilities:

1. Reject null pointers and lengths shorter than the fixed announce length.
2. Require HEADER_1 announce flags `0x01`, context `0x00`, and a payload that
   fits within `ANNOUNCE_RETICULUM_MDU`.
3. Extract destination hash, public key, name hash, random hash, signature, and
   app-data view without heap allocation.
4. Never read beyond `raw_packet[0:raw_len]`.

Verification:

- QEMU tests against `tests/harness/oracle.announce_parse`.
- Negative malformed-field and short-buffer tests.
- Symbolic bounds proof over all lengths up to the Reticulum MDU.

## announce_validate

Module: `announce`.

Inputs:

```
a0 = announce_rx_t* parsed
```

Outputs:

```
a0 = 0 on valid announce, negative errno on invalid announce
```

Responsibilities:

1. Compute `identity_hash = SHA256(public_key)[0:16]`.
2. Compute expected destination hash as `SHA256(name_hash || identity_hash)[0:16]`.
3. Compare expected destination hash to packet destination hash.
4. Verify Ed25519 signature over
   `destination_hash || public_key || name_hash || random_hash || app_data`
   using `public_key[32:64]` as the Ed25519 public key.
5. Reject every mismatch without updating transport state.

Verification:

- Pyca/upstream oracle tests for valid announces.
- Tamper tests for every signed field and destination-hash-only mismatch.
- TLA+ trace coverage through `transport_process_announce`.

## transport_path_init

Module: `transport`.

Inputs:

```
(none)
```

Outputs:

```
a0 = 0
```

Responsibilities:

1. Clear all path-table valid bits and reserved fields.
2. Leave no stale public key bytes observable through lookup.
3. Be idempotent.

## transport_path_update

Module: `transport`.

Inputs:

```
a0 = announce_rx_t* valid announce
a1 = interface_id
a2 = hops
```

Outputs:

```
a0 = 0 on inserted/updated, negative errno on invalid input
```

Responsibilities:

1. Update an existing destination hash if present.
2. Insert into the first invalid slot otherwise.
3. If full, evict the oldest entry by unsigned age from `last_seen_ms`.
4. Store destination hash, identity hash, public key, interface ID, hops, and
   current timestamp.

## transport_path_lookup

Module: `transport`.

Inputs:

```
a0 = destination_hash ptr (16 bytes)
a1 = transport_path_entry_t* out
```

Outputs:

```
a0 = 0 on found, negative errno on missing or invalid input
out = copied path entry on found
```

Responsibilities:

1. Search only valid entries.
2. Copy exactly one fixed-size entry on hit.
3. Leave `out` unchanged on miss.

## transport_process_announce

Module: `transport`.

Inputs:

```
a0 = raw packet ptr
a1 = raw packet len
a2 = interface_id
```

Outputs:

```
a0 = 0 accepted, positive duplicate/update status, negative invalid status
```

Responsibilities:

1. Parse the inbound announce.
2. Validate destination hash and signature.
3. Update the path table when valid.
4. Return stable status codes so `_main` can log accepted, duplicate, and
   rejected cases without inspecting private state.

## Boot Integration

The existing `_main` KISS frame path keeps the milestone-3 local command:

```
N || name_hash[10] || app_data
```

All other KISS frames still go through `packet_parse_header`. When the parsed
packet is a HEADER_1 announce, `_main` also calls
`transport_process_announce(kiss_buf, kiss_buf_len, TRANSPORT_INTERFACE_KISS)`.

Required logs:

| Case | Log sequence |
|------|--------------|
| Valid new path | `kiss.rx_frame`, `packet.parsed`, `transport.announce_valid`, `transport.path_updated` |
| Valid duplicate/update | `kiss.rx_frame`, `packet.parsed`, `transport.announce_valid`, `transport.path_updated` |
| Invalid announce | `kiss.rx_frame`, `packet.parsed`, `transport.announce_invalid` |
| Non-announce packet | existing `packet.parsed` or `packet.rejected` only |

Logs must not include private key material. Public destination/identity hashes
may be exposed in tests only if the harness needs them for assertion; default
runtime logs should remain status-only.

## Verifier Plan

- `proofs/transport/transport_state.tla` models announce RX as
  `Parse -> Validate -> UpdatePath | Reject` and covers duplicate/update and
  full-table eviction.
- `announce_parse` needs a bounds proof because it handles attacker-controlled
  lengths.
- `announce_validate` relies on the already verified SHA-256, destination hash,
  and Ed25519 verify primitives, plus end-to-end oracle tests.
- `transport_path_*` functions need symbolic memory proofs for bounded table
  search/update and unchanged-on-miss behavior.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| Upstream Reticulum announce acceptance has edge cases not captured by milestone 3 TX validation | Differential tests use upstream `RNS.Identity.validate_announce()` and pyca for every accepted case. |
| Path-table eviction policy becomes incompatible with later forwarding | Keep replacement deterministic and documented; persistence and multi-interface metrics are deferred until after this RAM table is proven. |
| Signature verification cost makes RX sluggish on C6 | Start with correctness; measure hardware KISS RX latency and defer batching/queueing until the transport state machine exists. |
| Logs accidentally expose peer public keys or app data | Default logs are status-only; tests parse emitted KISS/packet bytes rather than adding verbose runtime logs. |

## Retrospective

Milestone 5 completed as a tight vertical slice rather than the original
4-6 week estimate because the milestone-3 announce builder, Ed25519 verifier,
and milestone-4 flash/hardware baseline were already stable. The largest design
choice was to keep duplicate and eviction paths status-equivalent in runtime
logs (`transport.path_updated`) while retaining a positive return status from
`transport_process_announce` for callers that need to distinguish an existing
destination.

The path table remains RAM-only and intentionally small (`8` entries). That
keeps replacement deterministic and easy to prove, but persistence and richer
metrics must wait until later transport milestones. The TLA+ model tracks new,
duplicate, reject, and eviction state even when the observable log trace is the
same for accepted cases.

Final gates on 2026-05-03:

- `./verify announce_parse`, `./verify announce_validate`,
  `./verify transport_path_init`, `./verify transport_path_update`,
  `./verify transport_path_lookup`, `./verify transport_process_announce`, and
  `./verify _main` passed.
- `make ci` passed with `572 passed, 14 skipped`.
- `make build TARGET=qemu-virt` and `make build TARGET=c6` passed.
- `pytest --hardware tests/hardware/ -q -p no:cacheprovider` passed with
  `14 passed`.
- Stack maximum after boot integration: `2304 / 16384` bytes.
