# Milestone 7: Resource / Channel

- **Status:** Active
- **Started:** 2026-05-03
- **Estimate:** 4-6 weeks

## Goal

Carry structured application payloads over established Reticulum links. This
milestone extends the milestone-6 encrypted link path from a single generic
payload into bounded resource and channel packet handling: channel envelopes for
single-packet messages, resource advertisement parsing, part reception, and a
small in-RAM reassembly window.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Channel envelope | [channel envelope](#channel-envelope) | Forever |
| Resource advertisement subset | [resource advertisement](#resource-advertisement) | Development path through full resource transfer |
| Resource part parser | [resource parts](#resource-parts) | Forever |
| Resource reassembly window | [reassembly window](#reassembly-window) | Forever |
| Resource/channel dispatcher | [resource_process_plaintext](#resource_process_plaintext) | Development path through LoRa milestone |
| Resource state-machine proof | [verifier plan](#verifier-plan) | Forever |

## Definition of Done

- [ ] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-7 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `channel_envelope_build` and `channel_envelope_parse` round-trip the
      upstream `msgtype[2] || sequence[2] || length[2] || payload` envelope
      shape and reject malformed lengths without reading outside the caller
      buffer.
- [ ] `resource_advertisement_parse` accepts the strict Reticulum resource
      advertisement subset selected for this milestone and rejects unsupported
      msgpack keys, over-MDU advertisements, and inconsistent sizes.
- [x] `resource_part_parse` extracts one resource part from decrypted link
      plaintext, checks caller length bounds, and computes the map-hash used
      to infer the part position from the advertised receive window.
- [ ] `resource_reassembly_init` and `resource_reassembly_update` maintain a
      fixed-capacity in-RAM received-part window with deterministic duplicate,
      complete, and invalid statuses.
- [ ] `resource_process_plaintext` dispatches decrypted link plaintext for
      RESOURCE_ADV, RESOURCE, and CHANNEL contexts while preserving the
      milestone-6 context-0 encrypted packet path.
- [ ] A TLA+ resource/channel state model covers advertise, accept part,
      duplicate part, complete transfer, reject, and channel envelope accept
      traces.
- [ ] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`,
      `pytest --hardware tests/hardware/`, and `./verify <fn>` pass for every
      function added or modified in this milestone.

## Scope

Milestone 7 handles resource/channel traffic only after an encrypted link is
already established. It does not add LoRa transport, persistent resource
storage, retransmission timers, sliding windows beyond the fixed receive bitmap,
ratchets, IFAC, or LXMF semantics.

The first implementation may use a strict subset of upstream Reticulum resource
advertisements. Any unsupported upstream field or context must fail with a
negative test and a verifier-state transition.

## Channel Envelope

Module: `resource`.

Functions:

- `channel_envelope_build`
- `channel_envelope_parse`

Wire shape:

```
msgtype[2] || sequence[2] || payload_len[2] || payload[payload_len]
```

Responsibilities:

1. Use big-endian 16-bit fields, matching upstream `RNS.Channel.Envelope`.
2. Reject payloads that exceed the active link MDU.
3. Parse without copying payload bytes; return a bounded view into the caller
   buffer.

## Resource Advertisement

Module: `resource`.

Function:

- `resource_advertisement_parse`

Responsibilities:

1. Parse the selected strict subset of upstream `ResourceAdvertisement.pack()`
   fields: transfer size, data size, part count, resource hash, random hash,
   original hash, segment index, total segments, flags, and hashmap bytes.
2. Reject unsupported msgpack encodings and inconsistent part/hashmap lengths.
3. Leave compression, encryption, split resources, request/response flags, and
   metadata handling deferred unless explicitly enabled by tests.

## Resource Parts

Module: `resource`.

Function:

- `resource_part_parse`

Responsibilities:

1. Extract one decrypted RESOURCE context payload into a bounded part view.
2. Do not require an on-wire part index; RESOURCE payloads are raw part data,
   so reassembly infers the part position by matching the map-hash against the
   active advertisement window.
3. Hash each received part with SHA-256 truncated to the resource map-hash
   width selected for this milestone.

Verified parser shape:

1. `resource_part_parse(part_ptr, part_len, random_hash, out)` accepts parts up
   to the active link plaintext MDU and stores a non-copying payload view.
2. Empty parts may use a null payload pointer; non-empty parts reject null
   payload pointers.
3. The parser stores `SHA256(part_payload || random_hash)[0:4]`, matching
   upstream `Resource.MAPHASH_LEN == 4`.

## Reassembly Window

Module: `resource`.

Functions:

- `resource_reassembly_init`
- `resource_reassembly_update`

Responsibilities:

1. Maintain fixed-capacity in-RAM resource receive state without heap
   allocation.
2. Track received part bitmap/hashmap progress and return stable statuses for
   new part, duplicate part, complete resource, invalid part, and overflow.
3. Keep replacement deterministic if multiple inbound resources are active.

Verified state baseline:

1. `resource_reassembly_init` clears `resource_reassembly_table`.
2. The table has 2 fixed entries. Each entry reserves 64 received-part bits and
   64 upstream map hashes (`Resource.MAPHASH_LEN == 4`) for future
   `resource_reassembly_update` matching.
3. The initial receive-window constants mirror upstream Reticulum's receive
   window floor/default/max for this bounded subset: 2, 4, and 75.

## resource_process_plaintext

Module: `resource`.

Inputs:

```
a0 = link entry ptr
a1 = packet context byte
a2 = plaintext ptr
a3 = plaintext len
```

Outputs:

```
a0 = stable status code for accepted, duplicate, complete, channel, or invalid
```

Responsibilities:

1. Dispatch CHANNEL context to `channel_envelope_parse`.
2. Dispatch RESOURCE_ADV context to `resource_advertisement_parse`.
3. Dispatch RESOURCE context to `resource_part_parse` and
   `resource_reassembly_update`.

## Verifier Plan

- TLA+ model for advertisement, part receive, duplicate, completion, reject,
  and channel envelope accept traces.
- Bounds/source-shape proofs for every parser.
- Direct QEMU tests against Python oracle helpers for channel envelopes and the
  selected resource advertisement subset.
- Stateful QEMU tests for duplicate and complete resource-window transitions.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| Upstream resource advertisements use broader msgpack features than the first subset | Pin the accepted subset in tests; reject every unsupported encoding explicitly. |
| Resource transfer scope expands into retransmission or persistence | Keep this milestone receive-window only; timers and flash storage wait for a later resource milestone. |
| Channel and resource contexts require changes to `link_process_packet` | Keep link changes limited to passing decrypted context/plaintext into `resource_process_plaintext`; re-run all milestone-6 link gates. |
| Payload buffers become too large for static SRAM discipline | Use link MDU-derived maxima and one fixed receive window; add stack/static-size checks to CI gates. |
