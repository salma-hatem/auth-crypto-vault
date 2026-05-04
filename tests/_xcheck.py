"""
Developer-only cross-check against `hashlib`.

This script is GATED: it only runs when ACV_CROSSCHECK=1 is set in the
environment. It is NOT part of the graded test suite -- the project's
zero-library policy forbids using `hashlib` in the actual implementation.
This file exists only so the implementer can sanity-check bit-exactness
during development.

Usage:
    ACV_CROSSCHECK=1 python -m tests._xcheck
"""

import os
import sys

if os.environ.get("ACV_CROSSCHECK") != "1":
    # Silently no-op so accidental imports during a graded run do nothing.
    sys.exit(0)

import hashlib  # noqa: E402  -- only used in the gated dev path
import random  # noqa: E402

from . import _path_setup  # noqa: F401, E402

from sha512 import sha512, Sha512  # noqa: E402


def main() -> int:
    rng = random.Random(0xACEACE)
    fails = 0
    for i in range(50):
        n = rng.randint(0, 8192)
        msg = os.urandom(n)

        ours = sha512(msg)
        ref = hashlib.sha512(msg).digest()
        if ours != ref:
            fails += 1
            print(f"  one-shot MISMATCH at i={i} len={n}")
            continue

        # Streaming with a few odd chunk sizes.
        h = Sha512()
        offset = 0
        while offset < len(msg):
            step = rng.randint(1, 200)
            h.update(msg[offset:offset + step])
            offset += step
        if h.digest() != ref:
            fails += 1
            print(f"  streaming MISMATCH at i={i} len={n}")

    if fails == 0:
        print("ACV crosscheck: 50/50 inputs match hashlib.sha512 (one-shot + streaming).")
        return 0
    print(f"ACV crosscheck: {fails} mismatches")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
