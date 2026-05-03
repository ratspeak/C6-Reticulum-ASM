"""TARGET_C6 flash persistence contract tests.

The production flash dispatcher is not wired yet, so this module is a
hardware-marked contract anchor for milestone 4. Once `identity_save`,
`identity_load`, and the boot load-or-create path land, replace the explicit
skip with the reset-retention flow documented in docs/hardware/flash.md.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.hardware

FLASH_CHIP_SIZE = 0x0040_0000
FLASH_IDENTITY_ABS_OFFSET = 0x003F_F000
FLASH_IDENTITY_REGION_SIZE = 0x1000
FLASH_SECTOR_SIZE = 0x1000
FLASH_PAGE_SIZE = 0x100


def test_flash_contract_constants_are_aligned() -> None:
    assert FLASH_IDENTITY_ABS_OFFSET + FLASH_IDENTITY_REGION_SIZE == FLASH_CHIP_SIZE
    assert FLASH_IDENTITY_ABS_OFFSET % FLASH_SECTOR_SIZE == 0
    assert FLASH_IDENTITY_REGION_SIZE == FLASH_SECTOR_SIZE
    assert FLASH_SECTOR_SIZE % FLASH_PAGE_SIZE == 0


def test_identity_reset_retention_pending_dispatcher() -> None:
    pytest.skip(
        "pending milestone-4 C6 flash dispatcher; reset-retention flow is "
        "specified in docs/hardware/flash.md"
    )
