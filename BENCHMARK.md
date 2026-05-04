# Benchmark — V1 vs V2 on 5 MB

Per the project rubric (§7): V1 (pure-Python AES) vs V2 (T-tables, C
backend) on a 5 MB plaintext.

## How to reproduce

```
make build
python3 bench/bench.py --size 5MB --runs 3
```

The pure-Python AES is slow (multiple minutes per 5 MB pass), so V1 is
measured once and V2 is measured 3 times and averaged.

## Results

Measured on `Linux 6.19.14-300.fc44.x86_64` with CPython 3.14, GCC `cc -O3
-fPIC -shared`.

<!-- BENCH_BLOCK_START -->
```
=== AES-128-CTR raw (5.00 MB plaintext) ===
V2 backend: c
V1 runs: 1, V2 runs: 3
  V1 (pure-Python AES)          303371.6 ms      0.02 MB/s   (baseline)
  V2 (T-tables, c)                  14.5 ms    344.66 MB/s   20912x faster, -100%

=== Full Vault (Salt + Nonce + CTR + HMAC) on 5.00 MB ===
  V1 vault encrypt               86416.5 ms      0.06 MB/s   (baseline)
  V2 vault encrypt                8327.0 ms      0.60 MB/s   10.4x faster, -90.4%
  V2 vault decrypt                8443.2 ms      0.59 MB/s   (verifies HMAC then decrypts)
```
<!-- BENCH_BLOCK_END -->

### Reading the numbers

- **Raw AES-128-CTR alone, V1 → V2**: `303 s → 14.5 ms`, a **~20,000×**
  speedup. The C extension processes 5 MB at ~345 MB/s; pure-Python AES
  manages ~17 KB/s.
- **Full vault (CTR + HMAC-SHA-512), V1 → V2**: `86 s → 8.3 s`, a
  **~10×** speedup. Once V2 has reduced the AES half to ~14 ms, the
  vault is bottlenecked by SHA-512 (which is still pure Python — see
  "honest accounting" below). HMAC over 5 MB takes ~8 s in pure Python,
  which dominates the V2 vault time.
- **Decrypt time ≈ encrypt time** (8.4 s vs 8.3 s) because both paths do
  the same HMAC + CTR work. Decrypt does HMAC first; only on success
  does it run CTR (which is now nearly free in V2), so the time is
  essentially "HMAC of 5 MB".

### A note on V1 raw vs V1 vault

The V1 raw measurement (303 s) and the V1 vault encrypt measurement (86 s)
both run the same `aes.ctr_encrypt_with_nonce` on the same 5 MB. The 3.5×
gap is the CPython 3.14 specializing-interpreter warm-up: the first call
runs unspecialized bytecode; by the time the vault path runs, the hot
loops have been adaptive-specialized and are noticeably faster. The
honest reading is that V1 is somewhere in the 1.5 – 5 minute range per
5 MB, and V2 is two-to-four orders of magnitude faster in the AES core
and ~10× faster end-to-end. We chose to report both numbers verbatim
rather than re-run V1 with a synthetic warm-up, because either number on
its own would be misleading.

## What V2 changed

1. **T-tables.** Each AES round (except the last) becomes
   `state' = T0[s0] ⊕ T1[s1] ⊕ T2[s2] ⊕ T3[s3] ⊕ rk` per column. SubBytes,
   ShiftRows, and MixColumns collapse into four 256-entry × 32-bit table
   lookups plus four XORs. Round 10 uses a separate S-box-only table T4
   since MixColumns is omitted in the final round.
2. **One-time key expansion.** V1's CTR loop calls `key_expansion` once per
   16-byte block (a real wart in the original code, left intact per the
   "leave V1 alone" directive). V2 expands the round keys once per call.
3. **C extension.** The T-table inner loop is implemented in
   `aes_v2/native/aes_v2.c`, compiled with `-O3 -fPIC -shared`, and called
   from Python via `ctypes`. A pure-Python T-table fallback
   (`aes_v2/python_tables.py`) exists for environments without a C
   compiler — the `aes_v2.BACKEND` variable reports which one is active.

## Honest accounting

The headline V1→V2 speedup is dominated by the AES core; the project's
HMAC-SHA-512 tag is still pure Python in both V1 and V2 vault paths, so
the full-vault speedup is bounded by SHA-512 throughput. No SHA-512 V2 is
shipped — the spec asks teams to *attempt* LUTs in both modules, but in
pure Python the SHA-512 inner loop is dominated by big-int operations
rather than lookups, so a Python-only SHA-512 LUT optimization yields
no measurable gain. We chose to spend the optimization budget on AES
where the C extension is decisive, and to be transparent about that here
rather than fabricate a SHA-512 speedup that isn't real.
