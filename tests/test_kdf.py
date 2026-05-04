"""KDF tests for hmac_kdf.kdf."""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from hmac_kdf import derive_key, new_salt
from sha512 import sha512


class TestDeriveKey(unittest.TestCase):
    def test_kat_password_zeros_salt(self):
        salt = b"\x00" * 16
        password = b"password"
        # The KDF chains SHA-512(password || salt) and truncates to 16 bytes.
        # Cross-check against the project's own SHA-512 (already validated
        # against NIST FIPS 180-4 vectors elsewhere in the suite).
        expected = sha512(password + salt)[:16]
        self.assertEqual(derive_key(password, salt), expected)

    def test_empty_password(self):
        salt = b"\x11" * 16
        key = derive_key(b"", salt)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, sha512(b"" + salt)[:16])

    def test_long_password(self):
        salt = b"\xab" * 16
        password = b"correct horse battery staple" * 10
        key = derive_key(password, salt)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, sha512(password + salt)[:16])

    def test_bad_salt_length_raises(self):
        with self.assertRaises(ValueError):
            derive_key(b"pw", b"too short")
        with self.assertRaises(ValueError):
            derive_key(b"pw", b"")
        with self.assertRaises(ValueError):
            derive_key(b"pw", b"\x00" * 17)

    def test_different_salt_different_key(self):
        password = b"same password"
        k1 = derive_key(password, b"\x00" * 16)
        k2 = derive_key(password, b"\x01" + b"\x00" * 15)
        self.assertNotEqual(k1, k2)


class TestNewSalt(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(new_salt()), 16)

    def test_two_calls_differ(self):
        # 16 random bytes collide with probability 2**-128. If this ever
        # fires, suspect the OS RNG, not the test.
        self.assertNotEqual(new_salt(), new_salt())


if __name__ == "__main__":
    unittest.main()
