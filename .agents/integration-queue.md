# Integration Queue

## Session

- parallel session live — 2026-05-03T06:18:00Z; baseline `make ci` and `./verify --all` passed; milestone 3 is active

## Pending

- none

## Resolved (rolling, last 20)

- [agent-4] Add `proofs/crypto/x25519/x25519_montgomery_ladder.bsc` as a documented direct Binsec investigation; not appended to `@verify` because default `-sse-depth 524288` cuts the only path at depth 524299 / status unknown, while `-sse-depth 6000000` reports secure at max path depth 4788832 — branch: agent-4/x25519-montgomery-ladder-bsc, commit: 4672f2f, integrated as 496822f 2026-05-03T07:05:41Z
- [agent-6] Add Tier D announce TX trace model `proofs/announce/announce_tx.tla` + `proofs/announce/announce_tx.cfg`; TLC passes direct `tlc proofs/announce/announce_tx.tla` — branch: agent-6/announce-tx-tla, commit: ea19c4a, integrated as e9759ce 2026-05-03T07:01:29Z
- [agent-4] Add Tier B proof `proofs/crypto/x25519/x25519_field_inv.bsc` and append it to `src/crypto/x25519/x25519_field_inv.S` `@verify` — branch: agent-4/x25519-field-inv-bsc, commit: 5fff896, integrated as 9b0bba5 2026-05-03T07:00:27Z
- [agent-3] Add direct-call qemu coverage for `destination_name_hash` and `destination_hash` tests; asserts asm output bytes against hashlib/upstream vectors — branch: agent-3/destination-qemu-tests, commit: 68beaa1, integrated as 1e2a711 2026-05-03T06:46:52Z
- [agent-4] Add Tier B proof `proofs/crypto/x25519/x25519_field_mul.bsc` and append it to `src/crypto/x25519/x25519_field_mul.S` `@verify` — branch: agent-4/x25519-field-mul-bsc, commit: 5466201, integrated as 404102b 2026-05-03T06:45:29Z
- [agent-5] Merge milestone-3 Python oracle/test helpers for identity layout/hash, destination hash, HEADER_1 announce bytes, and pyca/upstream announce signature validation — branch: agent-5/work, commit: 4d26af0, integrated as 01c0301 2026-05-03T06:33:11Z
- [agent-3] Merge verified destination hash helpers `destination_name_hash` and `destination_hash` with upstream Reticulum vectors and Tier A Cryptol/SAW proofs — branch: agent-3/work, commit: d8b82ca, integrated as 2d53456 2026-05-03T06:33:11Z
- [agent-2] Merge verified `identity_hash` (SHA256(public_key[64])[0:16]) with QEMU pytest vectors and Tier A Cryptol/SAW proof — branch: agent-2/work, commit: af609b6, integrated as 7a846cb 2026-05-03T06:27:36Z
- [agent-4] Add Tier B proof `proofs/crypto/x25519/x25519_field_sq.bsc` and append it to `src/crypto/x25519/x25519_field_sq.S` `@verify` — branch: agent-4/work, commit: b529d7a, integrated as 902dbeb 2026-05-03T06:27:36Z
- [agent-6] Add shared Tier A Reticulum SHA-256 truncation helpers for milestone-3 identity/destination hash proofs: `proofs/identity/ReticulumIdentity.cry`, `proofs/destination/ReticulumDestination.cry`, `proofs/destination/reticulum_hash_helpers.saw` — branch: agent-6/m3-reticulum-hash-helpers, commit: 3de4826, integrated 2026-05-03T06:27:36Z
- [agent-4] Add Tier B proof `proofs/crypto/x25519/x25519_field_mul121665.bsc` and append it to `src/crypto/x25519/x25519_field_mul121665.S` `@verify` — branch: agent-4/work, commit: 8dffc2a, integrated 2026-05-03T06:24:00Z
- [agent-1] Created worktrees for agents 2-6 at `/Users/Games/Desktop/main/RISC-V-C6-agent-N` — branch: main
- [agent-1] Activated milestone 3 with `docs/milestones/milestone-3.md` and registry rows — commit f0de340
- [agent-1] Bootstrap parallel coordination: .agents files, FUNCTIONS.md Owner column, registry parser support, and baseline `make ci` — commit 4831451
