# Milestone 9: LXMF Foundation

- **Status:** Active
- **Started:** 2026-05-03
- **Estimate:** 6-8 weeks

## Goal

Add the first native LXMF layer on top of the verified Reticulum stack: bounded
LXMF message construction, parsing, message-id/signature validation, delivery
announce app-data, and single-message dispatch. Direct delivery is link-backed
in upstream LXMF/Reticulum, so this milestone treats Direct as an established
Link payload path and treats Opportunistic as the no-link packet path. It
deliberately targets the envelope and router foundation needed for real
messages before store-and-forward propagation, stamps, attachments, or RNode
compatibility mode.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|------------|
| LXMF constants and bounded structs | [wire subset](#wire-subset) | Forever |
| Payload MessagePack subset | [payload codec](#payload-codec) | Forever |
| Message ID and signature surface | [message-id-and-signatures](#message-id-and-signatures) | Forever |
| Direct/opportunistic envelope codec | [message-envelope-codec](#message-envelope-codec) | Forever |
| Delivery announce app-data | [delivery-announce-app-data](#delivery-announce-app-data) | Forever |
| Inbound delivery dispatch | [inbound-delivery-dispatch](#inbound-delivery-dispatch) | Forever |
| Router state model | [verifier-plan](#verifier-plan) | Forever |

## Definition of Done

- [ ] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-9 function with
      a source, tests, verifier artifact, and status `verified`.
- [ ] The implemented packed-message subset matches upstream LXMF
      `LXMessage.py`:
      `destination_hash(16) || source_hash(16) || signature(64) || msgpack([timestamp, title, content, fields])`.
      Direct Link packets carry this full packed message; Opportunistic packets
      strip the destination hash in transit and reconstruct it from the packet
      destination on receive.
- [x] Payload build/parse accepts the bounded MessagePack subset needed for
      timestamp, title, content, empty/custom fields, and optional stamp stripping
      for message-id/signature validation.
- [x] `lxmf_message_id` computes `SHA256(destination || source || payload_without_stamp)`
      and uses the exact payload bytes that were or will be signed.
- [ ] `lxmf_message_sign` and `lxmf_message_verify` sign/verify
      `destination || source || payload_without_stamp || message_id` with the
      existing Ed25519 identity stack.
- [ ] `lxmf_message_pack` and `lxmf_message_parse` round-trip Python LXMF
      direct/opportunistic KATs, including malformed/truncated/oversize rejection.
- [x] `lxmf_delivery_announce_build` emits the upstream delivery app-data subset
      `msgpack([display_name_or_nil, stamp_cost_or_nil])`.
- [ ] `lxmf_inbound_dispatch` accepts one payload delivered by an established
      Reticulum Link as Direct, or one non-link Opportunistic packet payload,
      reconstructs any stripped destination hash, rejects duplicate or invalid
      messages deterministically, and records one bounded inbound message slot.
- [ ] Direct send behavior never bypasses Link establishment: it either uses an
      active Link/backchannel supplied by the link layer or returns a stable
      pending/no-link status for later retry policy.
- [ ] A TLA+ LXMF router state model covers outbound build/sign/send,
      Direct-link-required send, inbound parse/verify/deliver, invalid
      signature rejection, duplicate rejection, and oversize rejection.
- [ ] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`,
      focused LXMF tests, `make registry`, `make stack`, and `git diff --check`
      pass.

## Scope

Milestone 9 implements the message foundation only. It does not add propagation
nodes, propagation sync, stamps/proof-of-work, tickets, paper messages, image or
file attachment rendering, persistent message stores, user-facing apps, BLE, or
RNode compatibility mode. It also does not turn Direct into raw packet delivery:
Direct remains a Link payload path per upstream Reticulum. USB RNode/KISS
compatibility remains a strong later milestone once the native radio stack and
LXMF layer have been validated.

The fixed payload limits are intentionally conservative and static. Title,
content, fields, packed payload, packed message, and inbound slots must have
compile-time caps; no heap allocation or unbounded MessagePack recursion is
allowed.

## Wire Subset

Reference:

- Upstream Python: `/Users/Games/Desktop/main/upstream/LXMF/LXMF/LXMessage.py`
- Local Rust reference: `/Users/Games/Desktop/main/rsLXMF/crates/lxmf-core/src/message.rs`
- Delivery notes: `/Users/Games/Desktop/main/docs/lxmf-message-delivery.md`
- Reticulum Link/Resource API:
  `/Users/Games/Desktop/main/docs/reticulum-manual/13-api-reference.md`
- Reticulum destination link callbacks:
  `/Users/Games/Desktop/main/docs/reticulum-manual/api/destination.md`

Constants:

- Destination hash: 16 bytes.
- Source hash: 16 bytes.
- Ed25519 signature: 64 bytes.
- Fixed LXMF overhead: 112 bytes.
- Opportunistic encrypted single-packet content target: 295 bytes under the
  default Reticulum parameters.
- Direct Link single-packet content target: 319 bytes under the default
  Reticulum parameters; larger direct messages remain out of milestone scope
  until the resource path is wired into LXMF routing.

## Payload Codec

Module: `lxmf`.

Functions:

- `lxmf_payload_build`
- `lxmf_payload_parse`

Implementation status:

- [x] `lxmf_payload_build` emits upstream-compatible MessagePack for bounded
      timestamp, title, content, and empty/custom fields.
- [x] `lxmf_payload_parse` accepts array4/array5 payloads, preserves bounded
      title/content/fields views, rejects unsupported nested fields, and exposes
      exact no-stamp bytes for message-id/signature validation.

Responsibilities:

1. Build the strict milestone subset `msgpack([timestamp_f64, title_bin,
   content_bin, fields_map])`.
2. Parse the same subset from caller-provided bytes into a static parsed struct
   containing views into the input plus copied bounded field metadata.
3. Accept a fifth stamp element for inbound parsing but provide a
   `payload_without_stamp` view/length for Python-compatible message-id and
   signature validation.
4. Reject unsupported MessagePack types, nested structures outside the allowed
   fields subset, malformed lengths, and all buffers above the configured caps.

## Message ID And Signatures

Module: `lxmf`.

Functions:

- `lxmf_message_id`
- `lxmf_message_sign`
- `lxmf_message_verify`

Responsibilities:

1. Compute `SHA256(destination_hash || source_hash || payload_without_stamp)`.
2. Sign `destination_hash || source_hash || payload_without_stamp || message_id`
   with the existing Ed25519 private identity material.
3. Verify the same signed bytes using a recalled source identity/public key.
4. Preserve constant-time behavior for secret identity material by composing only
   through already verified crypto primitives.

## Message Envelope Codec

Module: `lxmf`.

Functions:

- `lxmf_message_pack`
- `lxmf_message_parse`

Responsibilities:

1. Pack the full LXMF message as `dest_hash || source_hash || signature ||
   payload`.
2. Parse the same wire shape into a bounded `lxmf_message_t` view, calling
   `lxmf_payload_parse` and `lxmf_message_id`.
3. Return stable status codes for success, invalid argument, too short,
   malformed payload, oversize payload, and bad signature.
4. Preserve the exact inbound payload bytes for verification; do not
   re-serialize structured fields before verifying.
5. Keep transport-specific framing outside the packed message: Opportunistic
   send strips the leading destination hash when creating the Reticulum packet
   payload, while Direct send requires an active Link and carries the full
   packed message.

## Delivery Announce App Data

Module: `lxmf`.

Functions:

- `lxmf_delivery_announce_build`

Responsibilities:

1. Emit upstream-compatible delivery announce app-data:
   `msgpack([display_name_or_nil, stamp_cost_or_nil])`.
2. Bound display-name length and encode it as UTF-8 bytes.
3. Encode `nil` for unsupported or absent stamp cost; stamp enforcement itself
   remains out of scope for this milestone.

## Inbound Delivery Dispatch

Module: `lxmf`.

Functions:

- `lxmf_inbound_dispatch`

Responsibilities:

1. Accept one Direct payload only from an established Reticulum Link as a full
   LXMF packed message.
2. Accept one opportunistic payload by prefixing the packet destination hash
   before calling `lxmf_message_parse`, matching upstream router behavior.
3. Verify signature when the source identity is known, reject duplicates by
   message-id, and record one bounded inbound message slot for tests and later
   application hooks.
4. Return deterministic delivered, duplicate, invalid, unknown-source, and
   capacity statuses.

## Verifier Plan

- Source/bounds verifier for `lxmf_payload_build` and `lxmf_payload_parse`,
  backed by Python reference KATs generated from upstream LXMF/MessagePack.
- Source/bounds verifier for message pack/parse shape and error returns.
- KAT bridge for `lxmf_message_id`, `lxmf_message_sign`, and
  `lxmf_message_verify` against upstream Python LXMF and the existing Ed25519
  verifier.
- TLA+ model [proofs/lxmf/lxmf_router_state.tla](../../proofs/lxmf/lxmf_router_state.tla)
  for outbound/inbound/invalid/duplicate/oversize router traces.
- Direct qemu tests for every status branch, including no-link/pending Direct
  send behavior; hardware tests are optional because LXMF itself is
  transport-independent and the milestone-8 LoRa path already validates the
  physical interface.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| MessagePack generality can explode scope | Implement only the upstream LXMF subset required for direct/opportunistic messages, with explicit rejection of unsupported structures. |
| Signature bytes can drift if payloads are reserialized | Preserve original inbound payload bytes and strip only the optional fifth stamp element before hashing/signing. |
| Direct delivery can be mistaken for raw packet delivery | Pin the implementation to upstream behavior: Direct requires an established Reticulum Link; only Opportunistic uses the stripped single-packet path. |
| Full Direct delivery may require large resource transfers | Limit this milestone to single-message envelope behavior; resource-backed delivery integration follows after the foundation is verified. |
| LXMF app expectations may imply persistence or UI | Keep the chip as a transport/protocol node; persistent queues and app UI are separate product concerns. |
