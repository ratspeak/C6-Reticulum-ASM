"""Oracle wrappers around the upstream Python Reticulum reference (ADR-0005,
the `oracle` target).

For functions that have a reference implementation in upstream Python, the
harness can call into `RNS` directly to obtain expected outputs and assert
the asm produces the same bytes. These helpers sit between the test and
`RNS.*` so a test like::

    expected_frames = oracle.kiss_decode(stream)
    asm_frames = run_asm_kiss_decode(stream)
    assert asm_frames == expected_frames

is one line.

The oracle is intentionally minimal here. New helpers land alongside the
asm function they validate; over-fitting the API in advance buys nothing.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
from collections.abc import Iterable
from typing import Any

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD

IDENTITY_HASH_LEN = 16
IDENTITY_PRIVATE_LEN = 64
IDENTITY_PUBLIC_LEN = 64
X25519_KEY_LEN = 32
ED25519_KEY_LEN = 32

DESTINATION_NAME_HASH_LEN = 10
DESTINATION_HASH_LEN = 16
ANNOUNCE_RANDOM_HASH_LEN = 10
ANNOUNCE_SIGNATURE_LEN = 64
RETICULUM_MDU = 484

HEADER_1_ANNOUNCE_FLAGS = 0x01
HEADER_1_LINKREQUEST_FLAGS = 0x02
HEADER_1_HOPS = 0x00
PACKET_CONTEXT_NONE = 0x00
HEADER_1_ANNOUNCE_LEN = 19
HEADER_1_LINKREQUEST_LEN = 19
LINK_REQUEST_MTU = 500
LINK_REQUEST_MODE_AES256_CBC = 1
LINK_REQUEST_SIGNAL_LEN = 3
LINK_REQUEST_PAYLOAD_LEN = X25519_KEY_LEN + ED25519_KEY_LEN + LINK_REQUEST_SIGNAL_LEN
LINK_REQUEST_RAW_LEN = HEADER_1_LINKREQUEST_LEN + LINK_REQUEST_PAYLOAD_LEN


class OracleDependencyError(RuntimeError):
    """Raised when an optional upstream oracle dependency is unavailable."""


def _require(module_name: str) -> Any:
    """Import a module from the upstream Python reference, raising a clear
    error if RNS is not installed.
    """
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise RuntimeError(
            f"oracle requires upstream Reticulum: cannot import {module_name}; "
            "install with `pip install rns`"
        ) from exc


def _require_pyca() -> tuple[Any, Any, Any, Any]:
    """Import pyca/cryptography primitives used for Reticulum identities."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
    except ImportError as exc:
        raise OracleDependencyError(
            "oracle requires pyca/cryptography for key derivation, signing, "
            "and signature validation"
        ) from exc
    return x25519, ed25519, (Encoding.Raw, PublicFormat.Raw), InvalidSignature


def _bytes(name: str, value: bytes | bytearray | memoryview) -> bytes:
    try:
        return bytes(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be bytes-like") from exc


def _check_len(name: str, value: bytes, expected: int) -> bytes:
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")
    return value


def _hash_trunc(data: bytes, length: int) -> bytes:
    return hashlib.sha256(data).digest()[:length]


# -------------------------------------------------------------------------
# KISS — pure-Python reference for both encode and decode. Used by the kiss
# function tests in milestone 1.
# -------------------------------------------------------------------------


def kiss_encode(payload: bytes) -> bytes:
    """Frame `payload` with KISS escaping. Output starts and ends with FEND."""
    out = bytearray([KISS_FEND, 0x00])  # type 0 = data frame
    for b in payload:
        if b == KISS_FEND:
            out.extend([KISS_FESC, KISS_TFEND])
        elif b == KISS_FESC:
            out.extend([KISS_FESC, KISS_TFESC])
        else:
            out.append(b)
    out.append(KISS_FEND)
    return bytes(out)


def kiss_decode(stream: Iterable[int]) -> list[bytes]:
    """Decode a sequence of bytes (any iterable yielding ints 0..255) into
    frame payloads. Drops the type byte (KISS port/command). Raises ValueError
    on a malformed escape sequence.
    """
    frames: list[bytes] = []
    buf = bytearray()
    in_frame = False
    escaped = False
    saw_type = False

    for b in stream:
        if b == KISS_FEND:
            if in_frame and buf:
                frames.append(bytes(buf))
            buf.clear()
            in_frame = True
            saw_type = False
            escaped = False
            continue
        if not in_frame:
            continue
        if not saw_type:
            saw_type = True  # consume the type/command byte
            continue
        if escaped:
            if b == KISS_TFEND:
                buf.append(KISS_FEND)
            elif b == KISS_TFESC:
                buf.append(KISS_FESC)
            else:
                raise ValueError(f"bad escape: 0xDB 0x{b:02x}")
            escaped = False
            continue
        if b == KISS_FESC:
            escaped = True
            continue
        buf.append(b)
    return frames


# -------------------------------------------------------------------------
# Reticulum packet header — defer to the upstream parser. The asm parser
# must produce the same field values for the same input bytes.
# -------------------------------------------------------------------------


def packet_parse(buf: bytes) -> dict[str, Any]:
    """Parse a Reticulum packet header using the upstream Python reference.

    Returns a dict with the same field names the asm parser populates in
    its struct. We restrict the dict to fields milestone 1 cares about
    (header byte, hops, destination hash, payload offset/length); fuller
    field coverage is added in later milestones.
    """
    rns_packet = _require("RNS.Packet")
    pkt = _upstream_packet_from_raw(buf, rns_packet=rns_packet)
    return {
        "header_byte": buf[0],
        "hops": buf[1],
        "dest_hash": pkt.destination_hash,
        "packet_type": pkt.packet_type,
        "payload": pkt.data,
    }


# -------------------------------------------------------------------------
# Milestone 3 identity, destination and announce helpers.
# -------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class IdentityMaterial:
    """Reticulum identity bytes in the milestone-3 static-memory layout."""

    x25519_private: bytes
    x25519_public: bytes
    ed25519_seed: bytes
    ed25519_public: bytes

    def __post_init__(self) -> None:
        for field in (
            "x25519_private",
            "x25519_public",
            "ed25519_seed",
            "ed25519_public",
        ):
            value = _check_len(field, _bytes(field, getattr(self, field)), 32)
            object.__setattr__(self, field, value)

    @property
    def private_key(self) -> bytes:
        return self.x25519_private + self.ed25519_seed

    @property
    def public_key(self) -> bytes:
        return self.x25519_public + self.ed25519_public

    @property
    def hash(self) -> bytes:
        return identity_hash(self.public_key)

    def get_private_key(self) -> bytes:
        return self.private_key

    def get_public_key(self) -> bytes:
        return self.public_key


@dataclasses.dataclass(frozen=True)
class AnnounceOracle:
    """Parsed or built non-ratchet HEADER_1 announce material."""

    raw_packet: bytes
    destination_hash: bytes
    public_key: bytes
    name_hash: bytes
    random_hash: bytes
    signature: bytes
    app_data: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_packet", _bytes("raw_packet", self.raw_packet))
        object.__setattr__(
            self,
            "destination_hash",
            _check_len(
                "destination_hash",
                _bytes("destination_hash", self.destination_hash),
                DESTINATION_HASH_LEN,
            ),
        )
        object.__setattr__(
            self,
            "public_key",
            _check_len(
                "public_key",
                _bytes("public_key", self.public_key),
                IDENTITY_PUBLIC_LEN,
            ),
        )
        object.__setattr__(
            self,
            "name_hash",
            _check_len(
                "name_hash",
                _bytes("name_hash", self.name_hash),
                DESTINATION_NAME_HASH_LEN,
            ),
        )
        object.__setattr__(
            self,
            "random_hash",
            _check_len(
                "random_hash",
                _bytes("random_hash", self.random_hash),
                ANNOUNCE_RANDOM_HASH_LEN,
            ),
        )
        object.__setattr__(
            self,
            "signature",
            _check_len(
                "signature",
                _bytes("signature", self.signature),
                ANNOUNCE_SIGNATURE_LEN,
            ),
        )
        object.__setattr__(self, "app_data", _bytes("app_data", self.app_data))

    @property
    def signed_data(self) -> bytes:
        return announce_signed_data(
            self.destination_hash,
            self.public_key,
            self.name_hash,
            self.random_hash,
            self.app_data,
        )

    @property
    def payload(self) -> bytes:
        return announce_payload(
            self.public_key,
            self.name_hash,
            self.random_hash,
            self.signature,
            self.app_data,
        )


@dataclasses.dataclass(frozen=True)
class LinkRequestOracle:
    """Parsed or built current HEADER_1 link request material."""

    raw_packet: bytes
    destination_hash: bytes
    x25519_public: bytes
    ed25519_public: bytes
    mtu: int = LINK_REQUEST_MTU
    mode: int = LINK_REQUEST_MODE_AES256_CBC

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_packet", _bytes("raw_packet", self.raw_packet))
        object.__setattr__(
            self,
            "destination_hash",
            _check_len(
                "destination_hash",
                _bytes("destination_hash", self.destination_hash),
                DESTINATION_HASH_LEN,
            ),
        )
        object.__setattr__(
            self,
            "x25519_public",
            _check_len(
                "x25519_public",
                _bytes("x25519_public", self.x25519_public),
                X25519_KEY_LEN,
            ),
        )
        object.__setattr__(
            self,
            "ed25519_public",
            _check_len(
                "ed25519_public",
                _bytes("ed25519_public", self.ed25519_public),
                ED25519_KEY_LEN,
            ),
        )


def identity_private_key(x25519_private: bytes, ed25519_seed: bytes) -> bytes:
    """Return upstream-compatible private bytes: x25519_sk || ed25519_seed."""
    return (
        _check_len(
            "x25519_private",
            _bytes("x25519_private", x25519_private),
            X25519_KEY_LEN,
        )
        + _check_len(
            "ed25519_seed",
            _bytes("ed25519_seed", ed25519_seed),
            ED25519_KEY_LEN,
        )
    )


def identity_public_key(x25519_public: bytes, ed25519_public: bytes) -> bytes:
    """Return upstream-compatible public bytes: x25519_pk || ed25519_pk."""
    return (
        _check_len(
            "x25519_public",
            _bytes("x25519_public", x25519_public),
            X25519_KEY_LEN,
        )
        + _check_len(
            "ed25519_public",
            _bytes("ed25519_public", ed25519_public),
            ED25519_KEY_LEN,
        )
    )


def identity_hash(public_key: bytes) -> bytes:
    """Return Reticulum Identity.truncated_hash(public_key)."""
    public_key = _check_len(
        "public_key", _bytes("public_key", public_key), IDENTITY_PUBLIC_LEN
    )
    return _hash_trunc(public_key, IDENTITY_HASH_LEN)


def identity_from_private_bytes(private_key: bytes) -> IdentityMaterial:
    """Derive public identity material from x25519_sk || ed25519_seed."""
    private_key = _check_len(
        "private_key", _bytes("private_key", private_key), IDENTITY_PRIVATE_LEN
    )
    return identity_from_private_parts(
        private_key[:X25519_KEY_LEN], private_key[X25519_KEY_LEN:]
    )


def identity_from_private_parts(
    x25519_private: bytes, ed25519_seed: bytes
) -> IdentityMaterial:
    """Derive Reticulum public/private layout from raw private components."""
    x25519_private = _check_len(
        "x25519_private",
        _bytes("x25519_private", x25519_private),
        X25519_KEY_LEN,
    )
    ed25519_seed = _check_len(
        "ed25519_seed", _bytes("ed25519_seed", ed25519_seed), ED25519_KEY_LEN
    )
    x25519, ed25519, serialization, _invalid_signature = _require_pyca()
    encoding, public_format = serialization
    x_public = (
        x25519.X25519PrivateKey.from_private_bytes(x25519_private)
        .public_key()
        .public_bytes(encoding, public_format)
    )
    ed_public = (
        ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed)
        .public_key()
        .public_bytes(encoding, public_format)
    )
    return IdentityMaterial(x25519_private, x_public, ed25519_seed, ed_public)


def destination_name(app_name: str, *aspects: str) -> str:
    """Return Destination.expand_name(None, app_name, *aspects)."""
    if "." in app_name:
        raise ValueError("dots cannot be used in app names")
    name = app_name
    for aspect in aspects:
        if "." in aspect:
            raise ValueError("dots cannot be used in aspects")
        name += "." + aspect
    return name


def destination_name_hash(name: str | bytes) -> bytes:
    """Return SHA256(destination_name_utf8_without_identity_suffix)[0:10]."""
    name_bytes = name.encode("utf-8") if isinstance(name, str) else _bytes("name", name)
    return _hash_trunc(name_bytes, DESTINATION_NAME_HASH_LEN)


def destination_name_hash_from_parts(app_name: str, *aspects: str) -> bytes:
    return destination_name_hash(destination_name(app_name, *aspects))


def destination_hash(name_hash: bytes, identity_hash_bytes: bytes) -> bytes:
    """Return SHA256(name_hash || identity_hash)[0:16]."""
    name_hash = _check_len(
        "name_hash", _bytes("name_hash", name_hash), DESTINATION_NAME_HASH_LEN
    )
    identity_hash_bytes = _check_len(
        "identity_hash",
        _bytes("identity_hash", identity_hash_bytes),
        IDENTITY_HASH_LEN,
    )
    return _hash_trunc(name_hash + identity_hash_bytes, DESTINATION_HASH_LEN)


def destination_hash_from_name(name: str | bytes, identity_hash_bytes: bytes) -> bytes:
    return destination_hash(destination_name_hash(name), identity_hash_bytes)


def destination_hash_from_parts(
    identity_hash_bytes: bytes, app_name: str, *aspects: str
) -> bytes:
    return destination_hash(
        destination_name_hash_from_parts(app_name, *aspects), identity_hash_bytes
    )


def destination_hash_upstream(
    identity_hash_bytes: bytes, app_name: str, *aspects: str
) -> bytes:
    """Return upstream RNS.Destination.hash(identity_hash, app_name, *aspects)."""
    destination = _require("RNS.Destination")
    identity_hash_bytes = _check_len(
        "identity_hash",
        _bytes("identity_hash", identity_hash_bytes),
        IDENTITY_HASH_LEN,
    )
    return destination.Destination.hash(identity_hash_bytes, app_name, *aspects)


def ed25519_sign(ed25519_seed: bytes, message: bytes) -> bytes:
    ed25519_seed = _check_len(
        "ed25519_seed", _bytes("ed25519_seed", ed25519_seed), ED25519_KEY_LEN
    )
    message = _bytes("message", message)
    _x25519, ed25519, _serialization, _invalid_signature = _require_pyca()
    return ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed).sign(message)


def ed25519_verify(ed25519_public: bytes, signature: bytes, message: bytes) -> bool:
    ed25519_public = _check_len(
        "ed25519_public",
        _bytes("ed25519_public", ed25519_public),
        ED25519_KEY_LEN,
    )
    signature = _check_len(
        "signature", _bytes("signature", signature), ANNOUNCE_SIGNATURE_LEN
    )
    message = _bytes("message", message)
    _x25519, ed25519, _serialization, invalid_signature = _require_pyca()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed25519_public).verify(
            signature, message
        )
    except invalid_signature:
        return False
    return True


def announce_signed_data(
    destination_hash_bytes: bytes,
    public_key: bytes,
    name_hash: bytes,
    random_hash: bytes,
    app_data: bytes | None = b"",
) -> bytes:
    destination_hash_bytes = _check_len(
        "destination_hash",
        _bytes("destination_hash", destination_hash_bytes),
        DESTINATION_HASH_LEN,
    )
    public_key = _check_len(
        "public_key", _bytes("public_key", public_key), IDENTITY_PUBLIC_LEN
    )
    name_hash = _check_len(
        "name_hash", _bytes("name_hash", name_hash), DESTINATION_NAME_HASH_LEN
    )
    random_hash = _check_len(
        "random_hash", _bytes("random_hash", random_hash), ANNOUNCE_RANDOM_HASH_LEN
    )
    app_data = b"" if app_data is None else _bytes("app_data", app_data)
    return destination_hash_bytes + public_key + name_hash + random_hash + app_data


def announce_payload(
    public_key: bytes,
    name_hash: bytes,
    random_hash: bytes,
    signature: bytes,
    app_data: bytes | None = b"",
) -> bytes:
    public_key = _check_len(
        "public_key", _bytes("public_key", public_key), IDENTITY_PUBLIC_LEN
    )
    name_hash = _check_len(
        "name_hash", _bytes("name_hash", name_hash), DESTINATION_NAME_HASH_LEN
    )
    random_hash = _check_len(
        "random_hash", _bytes("random_hash", random_hash), ANNOUNCE_RANDOM_HASH_LEN
    )
    signature = _check_len(
        "signature", _bytes("signature", signature), ANNOUNCE_SIGNATURE_LEN
    )
    app_data = b"" if app_data is None else _bytes("app_data", app_data)
    return public_key + name_hash + random_hash + signature + app_data


def announce_wire_packet(destination_hash_bytes: bytes, payload: bytes) -> bytes:
    destination_hash_bytes = _check_len(
        "destination_hash",
        _bytes("destination_hash", destination_hash_bytes),
        DESTINATION_HASH_LEN,
    )
    payload = _bytes("payload", payload)
    return (
        bytes([HEADER_1_ANNOUNCE_FLAGS, HEADER_1_HOPS])
        + destination_hash_bytes
        + bytes([PACKET_CONTEXT_NONE])
        + payload
    )


def announce_build(
    identity: IdentityMaterial,
    name_hash: bytes,
    random_hash: bytes,
    app_data: bytes | None = b"",
) -> AnnounceOracle:
    """Build the milestone-3 non-ratchet HEADER_1 announce oracle."""
    if not isinstance(identity, IdentityMaterial):
        raise TypeError("identity must be IdentityMaterial")
    name_hash = _check_len(
        "name_hash", _bytes("name_hash", name_hash), DESTINATION_NAME_HASH_LEN
    )
    random_hash = _check_len(
        "random_hash", _bytes("random_hash", random_hash), ANNOUNCE_RANDOM_HASH_LEN
    )
    app_data = b"" if app_data is None else _bytes("app_data", app_data)
    dest_hash = destination_hash(name_hash, identity.hash)
    signed = announce_signed_data(
        dest_hash, identity.public_key, name_hash, random_hash, app_data
    )
    signature = ed25519_sign(identity.ed25519_seed, signed)
    payload = announce_payload(
        identity.public_key, name_hash, random_hash, signature, app_data
    )
    raw_packet = announce_wire_packet(dest_hash, payload)
    return AnnounceOracle(
        raw_packet=raw_packet,
        destination_hash=dest_hash,
        public_key=identity.public_key,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=signature,
        app_data=app_data,
    )


def announce_parse(raw_packet: bytes) -> AnnounceOracle:
    """Parse a non-ratchet HEADER_1 announce into oracle fields."""
    raw_packet = _bytes("raw_packet", raw_packet)
    min_len = (
        HEADER_1_ANNOUNCE_LEN
        + IDENTITY_PUBLIC_LEN
        + DESTINATION_NAME_HASH_LEN
        + ANNOUNCE_RANDOM_HASH_LEN
        + ANNOUNCE_SIGNATURE_LEN
    )
    if len(raw_packet) < min_len:
        raise ValueError(
            f"announce packet too short: got {len(raw_packet)}, need at least {min_len}"
        )
    if len(raw_packet) > RETICULUM_MDU:
        raise ValueError(
            f"announce packet exceeds Reticulum MDU: got {len(raw_packet)}, max {RETICULUM_MDU}"
        )
    if raw_packet[0] != HEADER_1_ANNOUNCE_FLAGS:
        raise ValueError(f"not a HEADER_1 announce: flags=0x{raw_packet[0]:02x}")
    if raw_packet[18] != PACKET_CONTEXT_NONE:
        raise ValueError(f"unsupported announce context: 0x{raw_packet[18]:02x}")

    dest_hash = raw_packet[2:18]
    payload = raw_packet[19:]
    public_key = payload[:IDENTITY_PUBLIC_LEN]
    pos = IDENTITY_PUBLIC_LEN
    name_hash = payload[pos:pos + DESTINATION_NAME_HASH_LEN]
    pos += DESTINATION_NAME_HASH_LEN
    random_hash = payload[pos:pos + ANNOUNCE_RANDOM_HASH_LEN]
    pos += ANNOUNCE_RANDOM_HASH_LEN
    signature = payload[pos:pos + ANNOUNCE_SIGNATURE_LEN]
    pos += ANNOUNCE_SIGNATURE_LEN
    app_data = payload[pos:]
    return AnnounceOracle(
        raw_packet=raw_packet,
        destination_hash=dest_hash,
        public_key=public_key,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=signature,
        app_data=app_data,
    )


def announce_validate_pyca(raw_packet: bytes) -> bool:
    """Validate destination hash and Ed25519 signature with pyca."""
    try:
        ann = announce_parse(raw_packet)
        expected_dest = destination_hash(ann.name_hash, identity_hash(ann.public_key))
        if ann.destination_hash != expected_dest:
            return False
        return ed25519_verify(
            ann.public_key[X25519_KEY_LEN:],
            ann.signature,
            ann.signed_data,
        )
    except (OracleDependencyError, TypeError, ValueError):
        return False


def link_request_signalling(
    mtu: int = LINK_REQUEST_MTU, mode: int = LINK_REQUEST_MODE_AES256_CBC
) -> bytes:
    """Return upstream RNS.Link.signalling_bytes(mtu, mode)."""
    rns_link = _require("RNS.Link")
    return bytes(rns_link.Link.signalling_bytes(mtu, mode))


def link_request_payload(
    x25519_public: bytes,
    ed25519_public: bytes,
    *,
    mtu: int = LINK_REQUEST_MTU,
    mode: int = LINK_REQUEST_MODE_AES256_CBC,
) -> bytes:
    x25519_public = _check_len(
        "x25519_public", _bytes("x25519_public", x25519_public), X25519_KEY_LEN
    )
    ed25519_public = _check_len(
        "ed25519_public", _bytes("ed25519_public", ed25519_public), ED25519_KEY_LEN
    )
    return x25519_public + ed25519_public + link_request_signalling(mtu, mode)


def link_request_build(
    destination_hash_bytes: bytes,
    x25519_public: bytes,
    ed25519_public: bytes,
    *,
    mtu: int = LINK_REQUEST_MTU,
    mode: int = LINK_REQUEST_MODE_AES256_CBC,
) -> LinkRequestOracle:
    """Build a current upstream HEADER_1 LINKREQUEST packet."""
    destination_hash_bytes = _check_len(
        "destination_hash",
        _bytes("destination_hash", destination_hash_bytes),
        DESTINATION_HASH_LEN,
    )
    payload = link_request_payload(
        x25519_public, ed25519_public, mtu=mtu, mode=mode
    )
    rns_packet = _require("RNS.Packet")
    rns_destination = _require("RNS.Destination")

    class _Destination:
        type = rns_destination.Destination.SINGLE

        def __init__(self, destination_hash_value: bytes) -> None:
            self.hash = destination_hash_value

    pkt = rns_packet.Packet(
        _Destination(destination_hash_bytes),
        payload,
        packet_type=rns_packet.Packet.LINKREQUEST,
    )
    pkt.pack()
    return LinkRequestOracle(
        raw_packet=bytes(pkt.raw),
        destination_hash=destination_hash_bytes,
        x25519_public=x25519_public,
        ed25519_public=ed25519_public,
        mtu=mtu,
        mode=mode,
    )


def link_request_parse(raw_packet: bytes) -> LinkRequestOracle:
    """Parse a current HEADER_1 LINKREQUEST packet."""
    raw_packet = _bytes("raw_packet", raw_packet)
    pkt = _upstream_packet_from_raw(raw_packet)
    if pkt.packet_type != _require("RNS.Packet").Packet.LINKREQUEST:
        raise ValueError(f"not a link request: type={pkt.packet_type}")
    if pkt.context != PACKET_CONTEXT_NONE:
        raise ValueError(f"unsupported link request context: 0x{pkt.context:02x}")
    if len(pkt.data) != LINK_REQUEST_PAYLOAD_LEN:
        raise ValueError(f"unsupported link request payload length: {len(pkt.data)}")
    mode = (pkt.data[X25519_KEY_LEN + ED25519_KEY_LEN] & 0xE0) >> 5
    mtu = (
        (pkt.data[X25519_KEY_LEN + ED25519_KEY_LEN] << 16)
        + (pkt.data[X25519_KEY_LEN + ED25519_KEY_LEN + 1] << 8)
        + pkt.data[X25519_KEY_LEN + ED25519_KEY_LEN + 2]
    ) & 0x1FFFFF
    return LinkRequestOracle(
        raw_packet=raw_packet,
        destination_hash=pkt.destination_hash,
        x25519_public=pkt.data[:X25519_KEY_LEN],
        ed25519_public=pkt.data[X25519_KEY_LEN:X25519_KEY_LEN + ED25519_KEY_LEN],
        mtu=mtu,
        mode=mode,
    )


def _upstream_packet_from_raw(raw_packet: bytes, *, rns_packet: Any | None = None) -> Any:
    rns_packet = rns_packet or _require("RNS.Packet")
    pkt = rns_packet.Packet.__new__(rns_packet.Packet)
    pkt.raw = _bytes("raw_packet", raw_packet)
    try:
        ok = pkt.unpack()
    except TypeError:
        ok = pkt.unpack(pkt.raw)
    if ok is False:
        raise ValueError("upstream Reticulum rejected malformed packet")
    pkt.rssi = None
    pkt.snr = None
    pkt.q = None
    pkt.receiving_interface = None
    return pkt


def announce_validate_upstream(
    raw_packet: bytes, *, only_validate_signature: bool = False
) -> bool:
    """Validate an announce using upstream RNS.Identity.validate_announce()."""
    rns_identity = _require("RNS.Identity")
    pkt = _upstream_packet_from_raw(raw_packet)
    return bool(
        rns_identity.Identity.validate_announce(
            pkt, only_validate_signature=only_validate_signature
        )
    )
