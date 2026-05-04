"""Bit-flip tamper detection demo for the final presentation."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault.vault import vault_encrypt_bytes, vault_decrypt_bytes, VaultError


REGIONS = [
    ("salt", 0),
    ("nonce", 16),
    ("ciphertext (first byte)", 28),
    ("HMAC tag (last byte)", -1),
]


def flip_bit(blob: bytes, offset: int) -> bytes:
    if offset < 0:
        offset = len(blob) + offset
    return blob[:offset] + bytes([blob[offset] ^ 0x01]) + blob[offset + 1:]


def main():
    plaintext = b"the quick brown fox jumps over the lazy dog\n" * 32
    password = b"demo-password"
    blob = vault_encrypt_bytes(plaintext, password)

    recovered = vault_decrypt_bytes(blob, password)
    assert recovered == plaintext, "untampered roundtrip should succeed"
    print(f"untampered roundtrip:           OK ({len(plaintext)} bytes recovered)")
    print()

    for name, offset in REGIONS:
        tampered = flip_bit(blob, offset)
        try:
            vault_decrypt_bytes(tampered, password)
        except VaultError as e:
            print(f"flip 1 bit in {name:<25} REJECTED -> {e}")
        else:
            print(f"flip 1 bit in {name:<25} *** SECURITY FAILURE: decryption succeeded ***")
            sys.exit(2)

    try:
        vault_decrypt_bytes(blob, b"wrong-password")
    except VaultError as e:
        print(f"wrong password                            REJECTED -> {e}")
    else:
        print("wrong password                            *** SECURITY FAILURE ***")
        sys.exit(2)

    print()
    print("All tamper / wrong-password attempts correctly rejected.")


if __name__ == "__main__":
    main()
