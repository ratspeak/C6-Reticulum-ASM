"""angr binary-equivalence verifier for aes_addroundkey."""
from __future__ import annotations

import random
import sys

import _aes_angr as A
from _aes_oracle import add_round_key

STATE_PTR = 0x10010000
RK_PTR    = 0x10020000


def main() -> int:
    proj = A.load_project()
    addr = A.find_symbol(proj, "aes_addroundkey")
    rng = random.Random(0xAE5)
    failures: list[str] = []

    for trial in range(8):
        st = bytes(rng.getrandbits(8) for _ in range(16))
        rk = bytes(rng.getrandbits(8) for _ in range(16))
        state = A.make_state(proj, addr,
                             regs={"a0": STATE_PTR, "a1": RK_PTR},
                             memory=[(STATE_PTR, st), (RK_PTR, rk)])
        pre = A.snapshot_callee_saved(state)
        end = A.run_until_ret(proj, state, budget=2000)
        if end is None:
            failures.append(f"trial {trial}: did not return")
            continue
        got = A.read_bytes(end, STATE_PTR, 16)
        want = add_round_key(st, rk)
        if got != want:
            failures.append(f"trial {trial}: state mismatch:\n    got:  {got.hex()}\n    want: {want.hex()}")
        rk_post = A.read_bytes(end, RK_PTR, 16)
        if rk_post != rk:
            failures.append(f"trial {trial}: round_key buffer modified")
        failures.extend(f"trial {trial}: {f}" for f in A.check_callee_saved(end, pre))

    if failures:
        print("FAIL: aes_addroundkey:")
        for f in failures: print(f"  - {f}")
        return 1
    print("PASS: aes_addroundkey (8 random trials, state XOR'd correctly, "
          "round_key untouched, callee-saved regs preserved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
