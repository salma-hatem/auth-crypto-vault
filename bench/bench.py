"""V1 vs V2 benchmark on a 5 MB random file (project requirement)."""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes import ctr_encrypt_with_nonce as v1_ctr_encrypt
from aes_v2 import ctr_encrypt as v2_ctr_encrypt, BACKEND
from vault.vault import vault_encrypt_bytes, vault_decrypt_bytes


def parse_size(s: str) -> int:
    s = s.strip().upper()
    if s.endswith("MB"):
        return int(float(s[:-2]) * 1024 * 1024)
    if s.endswith("KB"):
        return int(float(s[:-2]) * 1024)
    return int(s)


def time_it(fn, *args, **kwargs):
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return time.perf_counter() - t0, out


def bench_ctr(label, encrypt_fn, plaintext, key, nonce, runs):
    times = []
    last = None
    for _ in range(runs):
        dt, ct = time_it(encrypt_fn, plaintext, key, nonce)
        times.append(dt)
        last = ct
    return {
        "label": label,
        "mean": sum(times) / len(times),
        "min": min(times),
        "max": max(times),
        "runs": runs,
        "ciphertext": last,
    }


def fmt_row(name, mean, mb_per_s, vs_v1):
    return f"  {name:<28} {mean*1000:>9.1f} ms   {mb_per_s:>7.2f} MB/s   {vs_v1}"


def run(size_bytes: int, runs: int, data_path: str | None) -> int:
    if data_path and os.path.exists(data_path):
        with open(data_path, "rb") as f:
            plaintext = f.read()
    else:
        plaintext = os.urandom(size_bytes)
        if data_path:
            os.makedirs(os.path.dirname(data_path), exist_ok=True)
            with open(data_path, "wb") as f:
                f.write(plaintext)

    size_mb = len(plaintext) / (1024 * 1024)
    key = os.urandom(16)
    nonce = os.urandom(12)
    password = b"benchmark-password"

    # V1 pure-Python AES on 5 MB takes minutes, so we run it once;
    # V2 (the C extension or Python T-tables) is fast enough to run `runs` times.
    v1_runs = 1
    v2_runs = runs

    print(f"=== AES-128-CTR raw ({size_mb:.2f} MB plaintext) ===")
    print(f"V2 backend: {BACKEND}")
    print(f"V1 runs: {v1_runs}, V2 runs: {v2_runs}")
    sys.stdout.flush()

    v1 = bench_ctr("V1 (pure-Python AES)", v1_ctr_encrypt, plaintext, key, nonce, v1_runs)
    print(fmt_row(v1["label"], v1["mean"], size_mb / v1["mean"], "(baseline)"))
    sys.stdout.flush()

    v2 = bench_ctr(f"V2 (T-tables, {BACKEND})", v2_ctr_encrypt, plaintext, key, nonce, v2_runs)
    if v1["ciphertext"] != v2["ciphertext"]:
        print("ERROR: V1 and V2 ciphertexts disagree", file=sys.stderr)
        return 1

    speedup = v1["mean"] / v2["mean"]
    pct = (v1["mean"] - v2["mean"]) / v1["mean"] * 100
    print(fmt_row(v2["label"], v2["mean"], size_mb / v2["mean"],
                  f"{speedup:.1f}x faster, -{pct:.1f}%"))
    sys.stdout.flush()

    print()
    print(f"=== Full Vault (Salt + Nonce + CTR + HMAC) on {size_mb:.2f} MB ===")
    sys.stdout.flush()

    t0 = time.perf_counter()
    blob_v1 = vault_encrypt_bytes(plaintext, password, backend="v1")
    e1_mean = time.perf_counter() - t0
    print(fmt_row("V1 vault encrypt", e1_mean, size_mb / e1_mean, "(baseline)"))
    sys.stdout.flush()

    e2_times = []
    for _ in range(v2_runs):
        t0 = time.perf_counter()
        blob_v2 = vault_encrypt_bytes(plaintext, password, backend="v2")
        e2_times.append(time.perf_counter() - t0)
    e2_mean = sum(e2_times) / len(e2_times)
    print(fmt_row("V2 vault encrypt", e2_mean, size_mb / e2_mean,
                  f"{e1_mean/e2_mean:.1f}x faster, -{(e1_mean-e2_mean)/e1_mean*100:.1f}%"))
    sys.stdout.flush()

    d2_times = []
    for _ in range(v2_runs):
        t0 = time.perf_counter()
        recovered = vault_decrypt_bytes(blob_v2, password, backend="v2")
        d2_times.append(time.perf_counter() - t0)
    d2_mean = sum(d2_times) / len(d2_times)

    if recovered != plaintext:
        print("ERROR: Vault roundtrip mismatch", file=sys.stderr)
        return 1

    print(fmt_row("V2 vault decrypt", d2_mean, size_mb / d2_mean, "(verifies HMAC then decrypts)"))
    return 0


def main():
    p = argparse.ArgumentParser(description="V1 vs V2 AES-CTR benchmark.")
    p.add_argument("--size", default="5MB", help="plaintext size, e.g. 5MB, 1MB, 100KB")
    p.add_argument("--runs", type=int, default=3, help="repetitions per measurement")
    p.add_argument("--data", default="bench/data/bench.bin", help="path to cache the random plaintext")
    args = p.parse_args()
    sys.exit(run(parse_size(args.size), args.runs, args.data))


if __name__ == "__main__":
    main()
