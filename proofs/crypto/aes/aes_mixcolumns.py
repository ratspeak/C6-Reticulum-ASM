"""angr binary-equivalence verifier for aes_mixcolumns."""
from __future__ import annotations

import random
import sys

import _aes_angr as A
from _aes_oracle import mix_columns

STATE_PTR = 0x10010000


def main() -> int:
    proj = A.load_project()
    addr = A.find_symbol(proj, "aes_mixcolumns")
    rng = random.Random(0x4D_43)
    failures: list[str] = []

    # FIPS 197 §B.4 example column [0xdb, 0x13, 0x53, 0x45] expanded to a
    # full state (column 0), plus random states.
    vectors: list[tuple[str, bytes]] = [
        ("fips-b4-col0", bytes([0xdb, 0x13, 0x53, 0x45]) + b"\x00" * 12),
        ("all-zero",     b"\x00" * 16),
        ("identity",     bytes(range(16))),
    ]
    for i in range(8):
        vectors.append((f"random[{i}]", bytes(rng.getrandbits(8) for _ in range(16))))

    for name, st in vectors:
        state = A.make_state(proj, addr, regs={"a0": STATE_PTR},
                             memory=[(STATE_PTR, st)])
        pre = A.snapshot_callee_saved(state)
        end = A.run_until_ret(proj, state, budget=5000)
        if end is None:
            failures.append(f"{name}: did not return"); continue
        got = A.read_bytes(end, STATE_PTR, 16)
        want = mix_columns(st)
        if got != want:
            failures.append(f"{name}: state mismatch:\n    got:  {got.hex()}\n    want: {want.hex()}")
        failures.extend(f"{name}: {f}" for f in A.check_callee_saved(end, pre))

    if failures:
        print("FAIL: aes_mixcolumns:")
        for f in failures: print(f"  - {f}")
        return 1
    print(f"PASS: aes_mixcolumns ({len(vectors)} vectors).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
