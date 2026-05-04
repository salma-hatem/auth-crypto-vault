"""Vault roundtrip tests: encrypt → decrypt → exact recovery."""

import filecmp
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from vault import (
    vault_decrypt_bytes,
    vault_decrypt_file,
    vault_encrypt_bytes,
    vault_encrypt_file,
)


SIZES = [0, 1, 15, 16, 17, 100, 1024, 65536]


class TestRoundtripV1(unittest.TestCase):
    backend = "v1"

    def test_random_sizes_roundtrip(self):
        for n in SIZES:
            with self.subTest(size=n, backend=self.backend):
                pt = os.urandom(n)
                pw = os.urandom(24)
                blob = vault_encrypt_bytes(pt, pw, backend=self.backend)
                # On-disk format invariants:
                #   16 (salt) + 12 (nonce) + n (ct) + 64 (tag)
                self.assertEqual(len(blob), 16 + 12 + n + 64)
                recovered = vault_decrypt_bytes(blob, pw, backend=self.backend)
                self.assertEqual(recovered, pt)

    def test_repeat_encrypt_yields_distinct_blobs(self):
        pt = b"the same plaintext, every time"
        pw = b"same password"
        a = vault_encrypt_bytes(pt, pw, backend=self.backend)
        b = vault_encrypt_bytes(pt, pw, backend=self.backend)
        self.assertNotEqual(a, b, "fresh salt+nonce per call should diverge blobs")
        # Both still decrypt to the same plaintext under the same password.
        self.assertEqual(vault_decrypt_bytes(a, pw, backend=self.backend), pt)
        self.assertEqual(vault_decrypt_bytes(b, pw, backend=self.backend), pt)

    def test_file_based_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "plain.bin")
            ct_path = os.path.join(tmp, "vault.bin")
            out_path = os.path.join(tmp, "recovered.bin")
            data = os.urandom(4096)
            with open(in_path, "wb") as f:
                f.write(data)
            pw = b"file-roundtrip-pw"
            vault_encrypt_file(in_path, ct_path, pw, backend=self.backend)
            self.assertTrue(os.path.exists(ct_path))
            vault_decrypt_file(ct_path, out_path, pw, backend=self.backend)
            self.assertTrue(filecmp.cmp(in_path, out_path, shallow=False))


class TestRoundtripV2(TestRoundtripV1):
    backend = "v2"


if __name__ == "__main__":
    unittest.main()
