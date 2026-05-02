"""angr binary-equivalence verifier for aes_shiftrows."""
from __future__ import annotations

import random
import sys

import _aes_angr as A
from _aes_oracle import shift_rows

STATE_PTR = 0x10010000


def main() -> int:
    proj = A.load_project()
    addr = A.find_symbol(proj, "aes_shiftrows")
    rng = random.Random(0xA5_5A)
    failures: list[str] = []

    # Cover deterministic + random; the FIPS 197 §B.4 row-shift example
    # plus 8 random states.
    vectors: list[tuple[str, bytes]] = [
        ("identity-counter", bytes(range(16))),
        ("all-zero",         b"\x00" * 16),
        ("all-FF",           b"\xff" * 16),
    ]
    for i in range(8):
        vectors.append((f"random[{i}]", bytes(rng.getrandbits(8) for _ in range(16))))

    for name, st in vectors:
        state = A.make_state(proj, addr,
                             regs={"a0": STATE_PTR},
                             memory=[(STATE_PTR, st)])
        pre = A.snapshot_callee_saved(state)
        end = A.run_until_ret(proj, state, budget=2000)
        if end is None:
            failures.append(f"{name}: did not return")
            continue
        got = A.read_bytes(end, STATE_PTR, 16)
        want = shift_rows(st)
        if got != want:
            failures.append(f"{name}: state mismatch:\n    got:  {got.hex()}\n    want: {want.hex()}")
        failures.extend(f"{name}: {f}" for f in A.check_callee_saved(end, pre))

    if failures:
        print("FAIL: aes_shiftrows:")
        for f in failures: print(f"  - {f}")
        return 1
    print(f"PASS: aes_shiftrows ({len(vectors)} vectors, all callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
