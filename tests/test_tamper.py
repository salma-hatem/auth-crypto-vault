"""Tamper-detection tests: a single bit-flip in any region must be rejected."""

import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from vault import (
    VaultError,
    vault_decrypt_bytes,
    vault_decrypt_file,
    vault_encrypt_bytes,
)


PT = b"The vault must reject a tampered blob without leaking plaintext."
PW = b"hunter2"


def _flip_bit(blob: bytes, offset: int, bit: int = 0) -> bytes:
    arr = bytearray(blob)
    if offset < 0:
        offset += len(arr)
    arr[offset] ^= (1 << bit)
    return bytes(arr)


class TestBitFlipDetection(unittest.TestCase):
    def setUp(self):
        self.blob = vault_encrypt_bytes(PT, PW)
        # Sanity: untampered blob decrypts cleanly.
        self.assertEqual(vault_decrypt_bytes(self.blob, PW), PT)

    def _assert_tamper_rejected(self, offset: int, label: str):
        bad = _flip_bit(self.blob, offset)
        with self.assertRaises(VaultError, msg=f"{label}: bit-flip at {offset} not detected"):
            vault_decrypt_bytes(bad, PW)

    def test_flip_in_salt(self):
        # Salt lives at bytes [0..16). Flipping it changes the derived key,
        # which in turn changes the recomputed HMAC tag → mismatch.
        self._assert_tamper_rejected(0, "salt")

    def test_flip_in_nonce(self):
        # Nonce lives at bytes [16..28).
        self._assert_tamper_rejected(16, "nonce")

    def test_flip_in_ciphertext(self):
        # Ciphertext starts at offset 28; flip the first byte of it.
        self._assert_tamper_rejected(28, "ciphertext")

    def test_flip_in_tag(self):
        # Tag occupies the last 64 bytes.
        self._assert_tamper_rejected(len(self.blob) - 1, "tag")


class TestBadInputs(unittest.TestCase):
    def test_wrong_password(self):
        blob = vault_encrypt_bytes(PT, PW)
        with self.assertRaises(VaultError):
            vault_decrypt_bytes(blob, b"definitely not the password")

    def test_truncated_one_byte_off(self):
        blob = vault_encrypt_bytes(PT, PW)
        with self.assertRaises(VaultError):
            vault_decrypt_bytes(blob[:-1], PW)

    def test_truncated_below_minimum(self):
        # Anything shorter than 16+12+64 = 92 bytes is ill-formed.
        with self.assertRaises(VaultError):
            vault_decrypt_bytes(b"", PW)
        with self.assertRaises(VaultError):
            vault_decrypt_bytes(b"\x00" * 91, PW)

    def test_minimum_blob_with_zero_ciphertext_decrypts_only_if_authentic(self):
        # An attacker-supplied 92-byte all-zero blob must fail HMAC.
        with self.assertRaises(VaultError):
            vault_decrypt_bytes(b"\x00" * 92, PW)


class TestFileBasedTamperRejection(unittest.TestCase):
    """`vault_decrypt_file` must NOT create the output file on tag failure."""

    def _run(self, mutate, label: str):
        with tempfile.TemporaryDirectory() as tmp:
            ct_path = os.path.join(tmp, "vault.bin")
            out_path = os.path.join(tmp, "out.bin")  # MUST NOT be created
            blob = vault_encrypt_bytes(PT, PW)
            mutated = mutate(blob)
            with open(ct_path, "wb") as f:
                f.write(mutated)
            with self.assertRaises(VaultError, msg=label):
                vault_decrypt_file(ct_path, out_path, PW)
            self.assertFalse(
                os.path.exists(out_path),
                f"{label}: output file was created on auth failure",
            )

    def test_salt_flip_no_output(self):
        self._run(lambda b: _flip_bit(b, 0), "salt")

    def test_nonce_flip_no_output(self):
        self._run(lambda b: _flip_bit(b, 16), "nonce")

    def test_ciphertext_flip_no_output(self):
        self._run(lambda b: _flip_bit(b, 28), "ciphertext")

    def test_tag_flip_no_output(self):
        self._run(lambda b: _flip_bit(b, -1), "tag")


if __name__ == "__main__":
    unittest.main()
