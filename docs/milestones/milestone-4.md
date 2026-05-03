# Milestone 4: Flash persistence

- **Status:** Complete
- **Started:** 2026-05-03
- **Completed:** 2026-05-03
- **Estimate:** 2-3 weeks

## Goal

Persist the local Reticulum identity in a reserved flash sector so a node can
reboot without changing its address. This milestone adds a small bounded flash
driver, a durable identity record format, and load-or-create boot behavior that
keeps the milestone-3 announce path stable across resets.

## Deliverables

| Component | Spec section | Permanence |
|-----------|--------------|-----------|
| Flash layout and model | [flash layout](#flash-layout) | Forever |
| Flash read/write/erase driver | [flash driver](#flash-driver) | Forever |
| Identity record format | [identity record](#identity-record) | Forever |
| Identity save/load helpers | [identity persistence](#identity-persistence) | Forever |
| Boot load-or-create path | [boot integration](#boot-integration) | Forever |

## Definition of done

- [x] [FUNCTIONS.md](../../FUNCTIONS.md) lists every milestone-4 function with
      a source, tests, verifier artifact, and status `verified`.
- [x] `docs/hardware/flash.md` records the reserved identity sector, page and
      sector sizes, target-specific backend assumptions, and erase/write safety
      rules.
- [x] `flash_init`, `flash_read`, `flash_write_page`, and
      `flash_erase_sector` implement bounded operations over only the reserved
      project flash region.
- [x] QEMU tests prove erase -> read returns `0xff`, page writes round-trip,
      partial reads are bounds-checked, and attempts to set erased bits from
      `0` back to `1` fail without modifying storage.
- [x] `identity_save` writes the record format in this spec and
      `identity_load` accepts valid records while rejecting bad magic, version,
      checksum, length, and identity-hash fields.
- [x] `_main` loads an existing identity before creating a new one, emits
      `identity.loaded` or `identity.created`, and still sends an upstream-valid
      announce over KISS.
- [x] On TARGET_C6 hardware, an identity saved before reset is loaded after
      reset and has the same identity hash.
- [x] `make ci`, `make build TARGET=qemu-virt`, `make build TARGET=c6`, and
      `./verify <fn>` pass for every function added or modified in this
      milestone.

## Flash Layout

Milestone 4 reserves one 4 KiB sector for the identity record. The initial
implementation stores a single active record and rewrites it by erase-then-page
write. Wear leveling, multiple slots, and destination-cache storage are deferred
until transport state exists.

Constants live in `src/include/flash.S`:

```
FLASH_SECTOR_SIZE             4096
FLASH_PAGE_SIZE                256
FLASH_IDENTITY_REGION_SIZE    4096
FLASH_IDENTITY_RECORD_OFFSET     0
```

The qemu-virt backend may use a model buffer with the same erase/write
semantics. The TARGET_C6 backend must use the reserved flash region documented
in `docs/hardware/flash.md`; no caller may pass arbitrary chip offsets.

## Flash Driver

### flash_init

Module: `flash`.

Inputs:

```
(none)
```

Outputs:

```
a0 = 0 on success, negative errno on failure
```

Responsibilities:

1. Initialize the flash backend for the current target.
2. On qemu-virt, initialize the model region to erased bytes exactly once.
3. On TARGET_C6, validate that the reserved region is aligned to
   `FLASH_SECTOR_SIZE`.

### flash_read

Module: `flash`.

Inputs:

```
a0 = offset within reserved identity flash region
a1 = out ptr
a2 = len
```

Outputs:

```
a0 = 0 on success, negative errno on failure
out[0:len] = flash bytes
```

Responsibilities:

1. Reject `offset + len > FLASH_IDENTITY_REGION_SIZE`.
2. Copy bytes without heap allocation.
3. Permit zero-length reads as a no-op.

### flash_write_page

Module: `flash`.

Inputs:

```
a0 = offset within reserved identity flash region
a1 = src ptr
a2 = len
```

Outputs:

```
a0 = 0 on success, negative errno on failure
```

Responsibilities:

1. Reject zero-length writes, writes crossing `FLASH_PAGE_SIZE`, and writes
   outside the reserved identity region.
2. Reject any byte where `(old_byte & new_byte) != new_byte`; flash writes may
   only change `1` bits to `0` bits.
3. Leave storage unchanged on validation failure.

### flash_erase_sector

Module: `flash`.

Inputs:

```
a0 = sector offset within reserved identity flash region
```

Outputs:

```
a0 = 0 on success, negative errno on failure
```

Responsibilities:

1. Reject unaligned offsets and offsets outside the reserved identity region.
2. Set the entire sector to `0xff`.
3. Leave other memory unchanged.

Verification:

- QEMU model tests for bounds, erase value, page write semantics, and
  unchanged-on-failure behavior.
- Symbolic execution over the qemu-virt model for bounds checks and the
  no-0-to-1 write rule.
- TARGET_C6 ROM-helper backend builds into the C6 image, and
  `tests/hardware/test_flash_persistence.py` passes the erase/write/read
  reset-retention flow on the physical Feather.

## Identity Record

All multi-byte integers are little-endian.

| Byte range | Field | Value |
|------------|-------|-------|
| 0..3 | magic | ASCII `RID1` |
| 4 | version | `1` |
| 5 | flags | `0` |
| 6..7 | header_len | `48` |
| 8..11 | identity_len | `IDENTITY_T_SIZE` |
| 12..15 | reserved | zero |
| 16..47 | checksum | `SHA256(header_without_checksum || identity)` |
| 48..207 | identity | 160-byte `identity_t` |
| 208..255 | padding | `0xff` |

The checksum input is bytes `0..15`, then bytes `48..207`. The checksum field
itself is not included. Padding remains erased so future versions can append
metadata without forcing an immediate format expansion.

## Identity Persistence

### identity_save

Module: `identity`.

Inputs:

```
a0 = identity_t* identity
```

Outputs:

```
a0 = 0 on success, negative errno on failure
```

Responsibilities:

1. Validate `identity.hash == SHA256(identity.public_key)[0:16]`.
2. Build the 256-byte record in static scratch.
3. Erase the identity sector.
4. Write the record one flash page at a time.
5. Read back and verify the stored record.

### identity_load

Module: `identity`.

Inputs:

```
a0 = identity_t* out
```

Outputs:

```
a0 = 0 on success, negative errno on failure or missing identity
out = stored identity_t on success
```

Responsibilities:

1. Read the identity record.
2. Reject erased, malformed, unsupported-version, bad-length, or bad-checksum
   records.
3. Copy only the 160-byte identity into `out`.
4. Recompute and validate the identity hash.

Verification:

- QEMU round-trip against `identity_create`, `identity_save`, and
  `identity_load`.
- Negative tests for each rejected record field.
- Symbolic proof that load never copies beyond `IDENTITY_T_SIZE`.

## Boot Integration

After `rng_init`, `_main` calls `flash_init` and then `identity_load` into
`identity_current`. If load succeeds, `_main` emits `identity.loaded`. If load
returns missing identity, `_main` calls `identity_create`, then
`identity_save`, and emits `identity.created`. Other flash errors emit
`identity.error` and skip announce TX for that command.

The milestone-3 command format remains unchanged:

```
N || name_hash[10] || app_data
```

The announce sender must use the persisted identity when one exists.

## Risks Specific To This Milestone

| Risk | Mitigation |
|------|------------|
| ESP32-C6 flash writes may require cache-disable or ROM helper sequencing | Capture the exact TARGET_C6 backend in `docs/hardware/flash.md` before production asm; keep qemu model tests separate from hardware contracts. |
| A power loss during erase/write can destroy the only identity copy | Single-slot storage is acceptable for milestone 4; the record checksum makes corruption detectable, and multi-slot wear leveling is deferred explicitly. |
| QEMU cannot prove real reset retention | Require a TARGET_C6 hardware reset-retention test in addition to qemu-virt semantics. |
| Identity persistence may accidentally log secret bytes | Keep logs to status events only and include no key material or hashes beyond existing public identity hash tests. |

## Retrospective

Milestone 4 closed faster than estimated because the flash scope stayed narrow:
one identity sector, one record page, and no wear-leveling. The qemu model and
Python proof were enough to pin the public flash contract before the C6 backend
landed.

The physical C6 run caught the important hardware gap: the ROM flash helpers
reject reads until the ROM flash descriptor is configured by
`esp_rom_spiflash_config_param`. `flash_init` now installs the 4 MiB / 64 KiB /
4 KiB / 256-byte geometry before read/write/erase calls. The hardware
reset-retention test erases only `0x003ff000..0x003fffff`, creates and saves an
identity, resets without reflashing, and validates that the second announce uses
the same public identity.

Single-slot erase-then-write remains acceptable for this milestone. Multi-slot
wear leveling, destination-cache persistence, and path-cache persistence should
wait until the transport table semantics are stable in milestone 5.
