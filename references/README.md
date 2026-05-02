# References

Vendored reference material — specifications, papers, and source code that the project's
asm and verifier specs cite.

These are read-only reference inputs. They are vendored (not linked to upstream URLs) so
the project remains buildable and verifiable in isolation, even years from now when external
URLs may have rotted.

## Inventory

This directory is initially empty. Material is vendored here as it becomes needed by a
specific milestone, with provenance recorded below.

### Required by milestone 1

- [ ] **RISC-V Unprivileged ISA Specification** (volume I, latest ratified). Cited by ADR-0001.
- [ ] **RISC-V psABI specification** (ILP32). Cited by ADR-0001.
- [ ] **ESP32-C6 Technical Reference Manual** (Espressif, latest). Cited by milestone 1.
- [ ] **ESP32-C6 Datasheet** (Espressif, latest).
- [ ] **Adafruit ESP32-C6 Feather schematic and pinout PDF**. Cited by milestone 1.
- [ ] **KISS protocol specification** (Karn, 1986). Cited by ADR-0007 and milestone 1.
- [ ] **Reticulum Network Stack manual** (`MANUAL.md`, vendored from upstream). Cited by
      milestone 1 and beyond.
- [ ] **Upstream Reticulum Python source**, pinned to a specific commit. Used by oracle
      target. Vendored at `references/upstream/Reticulum/`.

### Required by milestone 2 (crypto)

- [ ] **FIPS 180-4** (SHA-256).
- [ ] **FIPS 197** (AES).
- [ ] **RFC 2104** (HMAC).
- [ ] **RFC 5869** (HKDF).
- [ ] **RFC 7748** (X25519).
- [ ] **RFC 8032** (Ed25519).
- [ ] **NIST CAVP test vectors** for each crypto primitive.
- [ ] **HACL\* relevant proofs** (for cross-reference).
- [ ] **fiat-crypto generated reference** for Curve25519 field arithmetic.

### Required by milestone 8 (LoRa)

- [ ] **SX1276 datasheet** (Semtech).
- [ ] **RFM95 module datasheet** (HopeRF).

### Provenance log

| File | Source URL (at time of vendoring) | SHA-256 | Vendored on |
|------|-----------------------------------|---------|-------------|
| (none yet) | | | |

When vendoring a file, add a row here with the source URL, the SHA-256 of the vendored copy,
and the date. This is the provenance audit trail.

## What does not belong here

- Generated outputs (vendor SDK headers, build artifacts, intermediate verifier outputs).
- Material under licenses that prohibit redistribution (note the license; if redistribution
  is forbidden, link to the upstream source and document acquisition steps in
  `acquisition.md`).
