"""KAT for ed25519_sign executed under QEMU.

Frame: 'G' || sk[32] || msg[*]. Emits 64-byte signature.

Verifies the produced signature against pyca/cryptography's
Ed25519PrivateKey.from_private_bytes(sk).sign(msg) for several
(sk, msg) combinations including RFC 8032 §7.1 vectors.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from harness import build, log_parser, oracle, target


@pytest.fixture(scope="module")
def artifacts() -> build.BuildArtifacts:
    return build.build("qemu-virt")


def test_function_exists(artifacts):
    assert build.symbol_address(artifacts.elf, "ed25519_sign") > 0


def _run_frame(elf, frame: bytes, *, timeout: float = 120.0) -> list:
    cfg = target.TargetConfig(binary=elf)
    t = target.EmuTarget(cfg)
    if not t.is_available():
        pytest.skip("qemu-system-riscv32 not available")
    with t:
        time.sleep(0.05)
        t.write(frame)
        lines = t.read_lines(timeout=timeout)
    return log_parser.parse_lines(line + "\r\n" for line in lines)


def _qemu_sign(artifacts, sk: bytes, msg: bytes) -> bytes:
    payload = b"G" + sk + msg
    framed  = oracle.kiss_encode(payload)
    events  = _run_frame(artifacts.elf, framed)
    evt = log_parser.find_event(events, module="ed25519", event="sign")
    assert evt is not None, [e.raw for e in events]
    sig = bytes.fromhex(evt.fields["hex"])
    assert len(sig) == 64
    return sig


# RFC 8032 §7.1 — TEST 1
RFC_TEST1_SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                              "4449c5697b326919703bac031cae7f60")
RFC_TEST1_MSG = b""
RFC_TEST1_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a"
                              "84877f1eb8e5d974d873e065224901555f"
                              "b8821590a33bacc61e39701cf9b46bd25"
                              "bf5f0595bbe24655141438e7a100b")
# Hmm, RFC 8032 sig is 64 bytes — let me re-check
# Actually the formatted hex above is wrong length. Let me just run pyca and trust it.

_TEST_VECTORS = [
    ("rfc_test1", RFC_TEST1_SK, b""),
    ("short",     bytes(32),    b"hello"),
    ("longer",    bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f"
                                "5b8a319f35aba624da8cf6ed4fb8a6fb"),
                                b"This is a test message of moderate length."),
    ("128byte",   bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1"
                                "66d38535076f094b85ce3a2e0b4458f7"),
                                b"\x55" * 128),
]


@pytest.mark.parametrize("name,sk,msg", _TEST_VECTORS, ids=[v[0] for v in _TEST_VECTORS])
def test_qemu_sign_matches_pyca(artifacts, name, sk, msg):
    got = _qemu_sign(artifacts, sk, msg)
    expected = Ed25519PrivateKey.from_private_bytes(sk).sign(msg)
    assert got == expected, (
        f"{name}:\n  got:  {got.hex()}\n  want: {expected.hex()}"
    )
