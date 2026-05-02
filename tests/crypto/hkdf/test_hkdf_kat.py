"""End-to-end KAT for HKDF-SHA-256 against RFC 5869 Appendix A vectors.

Two markers in `_main`:
    'E' || saltlen[1] || salt || ikm   →  PRK in `hkdf.extract` log line
    'X' || prk[32] || okmlen[1] || infolen[1] || info  →  OKM in `hkdf.expand`

Skipped if qemu-system-riscv32 is not available.
"""

from __future__ import annotations

import time

import pytest

from harness import build, log_parser, oracle, target

# RFC 5869 Appendix A.1 — basic test
A1 = {
    "ikm":  bytes.fromhex("0b" * 22),
    "salt": bytes.fromhex("000102030405060708090a0b0c"),
    "info": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    "L":    42,
    "prk":  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    "okm":  "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
}
# RFC 5869 Appendix A.2 — long inputs
A2 = {
    "ikm":  bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"),  # 80 bytes
    "salt": bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),  # 80 bytes
    "info": bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),  # 80 bytes
    "L":    82,
    "prk":  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    "okm":  "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87",
}
# RFC 5869 Appendix A.3 — zero-length salt and info
A3 = {
    "ikm":  bytes.fromhex("0b" * 22),
    "salt": b"",
    "info": b"",
    "L":    42,
    "prk":  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    "okm":  "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
}


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def _run(elf, frame: bytes, *, timeout: float = 3.0) -> list[log_parser.LogEvent]:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


@pytest.mark.parametrize("v", [A1, A2, A3], ids=["a1", "a2", "a3"])
def test_extract(artifacts: build.BuildArtifacts, v: dict) -> None:
    salt = v["salt"]
    ikm = v["ikm"]
    assert len(salt) <= 0xFF
    payload = b"E" + bytes([len(salt)]) + salt + ikm
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)

    e = log_parser.find_event(events, module="hkdf", event="extract")
    assert e is not None, [x.raw for x in events]
    assert e.fields.get("hex") == v["prk"], \
        f"PRK mismatch: got {e.fields.get('hex')}, want {v['prk']}"


@pytest.mark.parametrize("v", [A1, A2, A3], ids=["a1", "a2", "a3"])
def test_expand(artifacts: build.BuildArtifacts, v: dict) -> None:
    prk = bytes.fromhex(v["prk"])
    info = v["info"]
    L = v["L"]
    assert len(prk) == 32 and L <= 0xFF and len(info) <= 0xFF
    payload = b"X" + prk + bytes([L]) + bytes([len(info)]) + info
    framed = oracle.kiss_encode(payload)
    events = _run(artifacts.elf, framed)

    e = log_parser.find_event(events, module="hkdf", event="expand")
    assert e is not None, [x.raw for x in events]
    assert e.fields.get("hex") == v["okm"], \
        f"OKM mismatch: got {e.fields.get('hex')}, want {v['okm']}"
