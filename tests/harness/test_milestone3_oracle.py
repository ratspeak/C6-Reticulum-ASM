"""Milestone-3 identity, destination and announce oracle tests."""

from __future__ import annotations

import pytest

from harness import oracle


X25519_PRIVATE = bytes(range(32))
ED25519_SEED = bytes(range(32, 64))
X25519_PUBLIC = bytes.fromhex(
    "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1a"
    "d1ba6f3e2138285f"
)
ED25519_PUBLIC = bytes.fromhex(
    "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c"
    "89794bc9322966dd7"
)
IDENTITY_HASH = bytes.fromhex("aca31af0441d81dbec71e82da0b4b5f5")
FIXED_RANDOM_HASH = bytes(range(10))


def _identity() -> oracle.IdentityMaterial:
    pytest.importorskip("cryptography", reason="pyca required for identity derivation")
    return oracle.identity_from_private_parts(X25519_PRIVATE, ED25519_SEED)


def test_identity_layout_matches_reticulum_private_public_order() -> None:
    identity = _identity()
    assert identity.private_key == X25519_PRIVATE + ED25519_SEED
    assert identity.public_key == X25519_PUBLIC + ED25519_PUBLIC
    assert identity.hash == IDENTITY_HASH
    assert identity.get_private_key() == identity.private_key
    assert identity.get_public_key() == identity.public_key


@pytest.mark.parametrize(
    ("name", "name_hash_hex", "dest_hash_hex"),
    [
        (
            "rnstransport.nodes",
            "dd9b8ea0cbeffdd9639f",
            "3dfc97b47eaf477373c1149a7429459c",
        ),
        (
            "lxmf.delivery",
            "6ec60bc318e2c0f0d908",
            "82de33c3aa80110d9e5af20b6b7eda4f",
        ),
        (
            "ratspeak.test",
            "313fa38e7c1f06361db0",
            "099fb73ef535913cf95d9d6d5113105a",
        ),
    ],
)
def test_destination_hash_vectors(
    name: str, name_hash_hex: str, dest_hash_hex: str
) -> None:
    identity_hash = bytes.fromhex("00112233445566778899aabbccddeeff")
    name_hash = oracle.destination_name_hash(name)
    assert name_hash == bytes.fromhex(name_hash_hex)
    assert oracle.destination_hash(name_hash, identity_hash) == bytes.fromhex(
        dest_hash_hex
    )


def test_destination_name_rejects_dots_inside_components() -> None:
    with pytest.raises(ValueError):
        oracle.destination_name("lxmf.delivery")
    with pytest.raises(ValueError):
        oracle.destination_name("lxmf", "deliver.y")


def test_announce_builds_header1_wire_image_and_valid_signature() -> None:
    identity = _identity()
    name_hash = oracle.destination_name_hash_from_parts("lxmf", "delivery")
    app_data = b"hello"

    announce = oracle.announce_build(identity, name_hash, FIXED_RANDOM_HASH, app_data)

    assert announce.raw_packet[0] == oracle.HEADER_1_ANNOUNCE_FLAGS
    assert announce.raw_packet[1] == oracle.HEADER_1_HOPS
    assert announce.raw_packet[2:18] == announce.destination_hash
    assert announce.raw_packet[18] == oracle.PACKET_CONTEXT_NONE
    assert announce.payload == announce.raw_packet[19:]
    assert announce.public_key == identity.public_key
    assert announce.name_hash == name_hash
    assert announce.random_hash == FIXED_RANDOM_HASH
    assert announce.app_data == app_data
    assert oracle.announce_validate_pyca(announce.raw_packet)


def test_announce_parse_round_trips_empty_app_data() -> None:
    identity = _identity()
    name_hash = oracle.destination_name_hash("rnstransport.nodes")
    announce = oracle.announce_build(identity, name_hash, FIXED_RANDOM_HASH, b"")

    parsed = oracle.announce_parse(announce.raw_packet)

    assert parsed == announce
    assert len(parsed.raw_packet) == 19 + 64 + 10 + 10 + 64
    assert oracle.announce_validate_pyca(parsed.raw_packet)


def test_announce_validation_rejects_tampered_signature_material() -> None:
    identity = _identity()
    name_hash = oracle.destination_name_hash("ratspeak.test")
    announce = oracle.announce_build(identity, name_hash, FIXED_RANDOM_HASH, b"payload")
    tampered = bytearray(announce.raw_packet)
    tampered[-1] ^= 0x01

    assert not oracle.announce_validate_pyca(bytes(tampered))


def test_upstream_destination_hash_parity_when_rns_available() -> None:
    pytest.importorskip("RNS", reason="upstream Reticulum required for parity check")
    identity_hash = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert oracle.destination_hash_upstream(identity_hash, "rnstransport", "nodes") == (
        oracle.destination_hash_from_parts(identity_hash, "rnstransport", "nodes")
    )
    assert oracle.destination_hash_upstream(identity_hash, "lxmf", "delivery") == (
        oracle.destination_hash_from_parts(identity_hash, "lxmf", "delivery")
    )


@pytest.mark.parametrize("app_data", [b"", b"hello"])
def test_upstream_announce_validation_when_rns_available(app_data: bytes) -> None:
    pytest.importorskip("RNS", reason="upstream Reticulum required for announce validation")
    identity = _identity()
    name_hash = oracle.destination_name_hash("lxmf.delivery")
    announce = oracle.announce_build(identity, name_hash, FIXED_RANDOM_HASH, app_data)

    assert oracle.announce_validate_upstream(announce.raw_packet)
