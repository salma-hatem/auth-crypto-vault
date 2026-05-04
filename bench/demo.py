"""Real-time demo of the Authenticated Cryptographic Vault.

Runs in ~10 seconds. Touches every requirement of the project spec:

    1. AES-128 against FIPS 197 vectors.
    2. SHA-512 against the FIPS 180-4 'abc' vector.
    3. HMAC-SHA-512 against an RFC 4231 vector.
    4. V1 vs V2 timing on a small plaintext (live).
    5. End-to-end vault encrypt + decrypt round-trip.
    6. Bit-flip tamper rejection in salt / nonce / ciphertext / tag.

Use `make bench` for the full 5 MB benchmark; this script is for the
classroom demo.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes import AES_encrypt, ctr_encrypt_with_nonce as v1_ctr
from aes_v2 import ctr_encrypt as v2_ctr, BACKEND
from sha512 import sha512
from hmac_kdf import hmac_sha512
from vault.vault import vault_encrypt_bytes, vault_decrypt_bytes, VaultError


GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def section(title):
    print()
    print(f"{BOLD}── {title} ──{RESET}")


def passed(label, why=""):
    suffix = f"  {DIM}{why}{RESET}" if why else ""
    print(f"  {GREEN}✓{RESET} {label}{suffix}")


def failed(label, why=""):
    suffix = f"  {RED}{why}{RESET}" if why else ""
    print(f"  {RED}✗{RESET} {label}{suffix}")
    sys.exit(1)


def expect(cond, label, why=""):
    (passed if cond else failed)(label, why)


def hexbytes(s):
    return bytes.fromhex(s.replace(" ", ""))


def main():
    print(f"{BOLD}Authenticated Cryptographic Vault — live demo{RESET}")
    print(f"{DIM}V2 backend: {BACKEND}{RESET}")

    section("1. AES-128 vs NIST FIPS 197")
    key = hexbytes("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = hexbytes("3243f6a8885a308d313198a2e0370734")
    ct_expected = hexbytes("3925841d02dc09fbdc118597196a0b32")
    expect(AES_encrypt(pt, key) == ct_expected, "FIPS 197 Appendix B (encrypt KAT)")

    section("2. SHA-512 vs FIPS 180-4")
    expected = hexbytes(
        "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a "
        "2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"
    )
    expect(sha512(b"abc") == expected, "SHA-512(\"abc\") = FIPS 180-4 App. C.1")

    section("3. HMAC-SHA-512 vs RFC 4231")
    rfc_key = bytes.fromhex("0b" * 20)
    rfc_data = b"Hi There"
    rfc_tag = hexbytes(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    )
    expect(hmac_sha512(rfc_key, rfc_data) == rfc_tag, "RFC 4231 case 1")

    section("4. V1 (pure-Python) vs V2 (T-tables, " + BACKEND + ")")
    size = 256 * 1024  # 256 KiB — V1 ~2 s, V2 sub-millisecond
    print(f"  {DIM}plaintext: {size // 1024} KiB random{RESET}")
    plaintext = os.urandom(size)
    aes_key = os.urandom(16)
    nonce = os.urandom(12)

    print(f"  {DIM}running V1 (this is the slow one — feel free to wait){RESET}", flush=True)
    t0 = time.perf_counter()
    ct_v1 = v1_ctr(plaintext, aes_key, nonce)
    v1_dt = time.perf_counter() - t0

    t0 = time.perf_counter()
    ct_v2 = v2_ctr(plaintext, aes_key, nonce)
    v2_dt = time.perf_counter() - t0

    expect(ct_v1 == ct_v2, "V1 and V2 produce identical ciphertext")
    speedup = v1_dt / v2_dt if v2_dt > 0 else float("inf")
    mb = size / (1024 * 1024)
    print(f"    {DIM}V1: {v1_dt * 1000:8.1f} ms   ({mb / v1_dt:.3f} MB/s){RESET}")
    print(f"    {DIM}V2: {v2_dt * 1000:8.3f} ms   ({mb / v2_dt:.2f} MB/s){RESET}")
    print(f"    {GREEN}{BOLD}V2 is {speedup:.0f}× faster on the same plaintext{RESET}")

    section("5. End-to-end Vault round-trip")
    secret = b"the launch codes are 0000\n"
    password = b"correcthorsebatterystaple"
    blob = vault_encrypt_bytes(secret, password)
    salt, nonce_bytes, ct_only = blob[:16], blob[16:28], blob[28:-64]
    print(f"  {DIM}blob layout: salt(16) nonce(12) ct({len(ct_only)}) tag(64){RESET}")
    print(f"  {DIM}salt  = {salt.hex()}{RESET}")
    print(f"  {DIM}nonce = {nonce_bytes.hex()}{RESET}")
    print(f"  {DIM}tag   = {blob[-64:].hex()[:32]}…{RESET}")
    recovered = vault_decrypt_bytes(blob, password)
    expect(recovered == secret, "round-trip recovers exact plaintext")

    section("6. Tamper rejection (bit-flip)")
    regions = [("salt", 0), ("nonce", 16), ("ciphertext byte 0", 28), ("HMAC tag", -1)]
    for name, off in regions:
        if off < 0:
            off = len(blob) + off
        bad = blob[:off] + bytes([blob[off] ^ 0x01]) + blob[off + 1:]
        try:
            vault_decrypt_bytes(bad, password)
        except VaultError:
            passed(f"flip 1 bit in {name:<18} → REJECTED, no plaintext produced")
        else:
            failed(f"flip 1 bit in {name}", "decryption succeeded — SECURITY FAILURE")

    try:
        vault_decrypt_bytes(blob, b"wrong-password")
    except VaultError:
        passed("wrong password               → REJECTED via HMAC mismatch")
    else:
        failed("wrong password", "decryption succeeded — SECURITY FAILURE")

    print()
    print(f"{GREEN}{BOLD}All checks green.{RESET}")


if __name__ == "__main__":
    main()
