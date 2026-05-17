# Authenticated Cryptographic Vault (ACV)

CIE 582 — Cryptography, Spring 2026.

A from-scratch implementation of an Encrypt-then-MAC vault that stores files
under AES-128-CTR with HMAC-SHA-512 authentication. Two implementations of
the AES core are provided: a pure-Python V1 baseline, and a V2 that uses the
Daemen/Rijmen 4× T-table approach (built as a small C shared library and
called from Python via `ctypes`, with a pure-Python T-table fallback).

## Zero-library policy

No external cryptographic libraries are used. The only third-party-style
dependency is the C compiler used to build the V2 shared library, which
compiles `aes_v2/native/aes_v2.c` — a file we wrote. There is no use of
`hashlib`, `hmac`, `cryptography`, `pycryptodome`, OpenSSL, or AES-NI
intrinsics. Standard-library modules used: `os` (for `os.urandom`), `sys`,
`argparse`, `getpass`, `struct`, `ctypes`, `time`, `unittest`.

## Repository layout

```
aes/                  V1 AES-128 (pure Python) — block cipher, key schedule,
                      S-box, GF(2^8) math, MixColumns, CTR mode.
aes_v2/               V2 AES-128-CTR using the 4× T-table approach.
  native/aes_v2.c       From-scratch C implementation (T-tables computed
                        at first call from the FIPS 197 S-box and xtime).
  python_tables.py      Pure-Python T-table fallback.
  native_wrapper.py     ctypes binding for the .so.
  __init__.py           Backend selector — exports `ctr_encrypt`,
                        `ctr_decrypt`, `BACKEND` ("c" or "python").
sha512/               SHA-512 (FIPS 180-4) — 80-round compression with
                      streaming Sha512 class.
hmac_kdf/             HMAC-SHA-512 (FIPS 198-1 / RFC 4231) and the KDF
                      First16Bytes(SHA-512(password || salt)).
vault/                File format, library functions, CLI.
tests/                NIST + RFC test vectors, vault roundtrip, tamper.
bench/                5 MB V1-vs-V2 benchmark, bit-flip demo.
```

## GUI

An interactive browser interface for the vault — five screens:
**Encrypt**, **Decrypt**, **Internals** (live KDF + NIST KATs), **Benchmark**, and **Tamper Demo**.

```bash
make build   # compile the C extension (optional — enables the fast V2 backend)
make gui     # installs Flask, then opens http://127.0.0.1:5000
```

`make gui` automatically installs Flask via pip if it is not already present.
If you prefer to manage dependencies manually:

```bash
pip install flask
python gui/server.py
```

The GUI serves the React frontend from `gui/static/` via a local Flask server.
All cryptography runs in the same Python process — no external crypto library is used.

## Build

```
make build       # compile aes_v2/native/libaes_v2.so
make test        # run the full unittest suite
make bench       # 5 MB V1 vs V2 AES-CTR benchmark
make demo-tamper # bit-flip rejection demo
```

If the C extension cannot be built (no compiler available), `aes_v2`
automatically falls back to `python_tables.py`. The benchmark labels which
backend ran.

## CLI

```
python -m vault encrypt --in plaintext.bin --out vault.bin
python -m vault decrypt --in vault.bin     --out recovered.bin
python -m vault encrypt --in pt --out ct --password-file pw.txt --backend v2
```

Password handling:
- `--password-file PATH` — read from file (trailing newline trimmed).
- `--password STRING` — direct on the command line. Strongly discouraged;
  it is logged in shell history and visible in the process listing.
- Otherwise the CLI prompts on stdin via `getpass`.

`--backend v1` (default) uses the pure-Python AES; `--backend v2` uses the
T-table backend (C if available, otherwise pure-Python tables).

## File format

```
[ Salt 16 B ][ Nonce 12 B ][ Ciphertext N B ][ HMAC tag 64 B ]
```

The HMAC-SHA-512 tag is computed over `Salt || Nonce || Ciphertext`. On
decryption the tag is verified **before** any plaintext is produced — a
mismatched tag aborts the operation with exit code 2 and no output file
is written. Tag comparison is constant-time.

## Cryptographic choices

- **AES-128-CTR.** 96-bit nonce, 32-bit big-endian counter starting at 0.
  Both salt and nonce are freshly generated per encryption via `os.urandom`.
- **KDF.** `key = sha512(password || salt)[:16]`.
- **HMAC.** Uses the AES key (16 B) zero-padded to 128 B (the SHA-512
  internal block size) before XOR with `ipad`/`opad`, per the project spec.
- **No padding.** CTR mode is a stream cipher; ciphertext length equals
  plaintext length exactly.

## Test vectors covered

- AES-128: FIPS 197 Appendix B and Appendix C.1 (single-block KAT both
  directions).
- AES-128-CTR: NIST SP 800-38A §F.5.1 four-block keystream and
  ciphertext check.
- SHA-512: FIPS 180-4 Appendix C.1 (`"abc"`), C.2 and C.3 (two-block
  vectors), the empty string, the 1-million-`a` vector, and length
  edge cases.
- HMAC-SHA-512: RFC 4231 cases 1, 2, 4, 5 (truncation, 128-bit prefix
  per the RFC), 6, 7.
- Vault: roundtrip across plaintext sizes 0 – 64 KiB for both backends,
  bit-flip rejection in salt / nonce / ciphertext / tag, wrong-password
  rejection, truncated-file rejection.

## Test summary

```
$ make test
...
Ran 62 tests in ~5s
OK
```

## Benchmark

See `BENCHMARK.md` for the V1 vs V2 numbers measured on a 5 MB plaintext
(per the project rubric's benchmark requirement).
