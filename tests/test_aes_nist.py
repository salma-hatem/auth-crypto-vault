import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from aes import AES_encrypt, AES_decrypt


class TestAES128FIPS197(unittest.TestCase):
    """NIST FIPS 197 known-answer test vectors for AES-128."""

    def test_appendix_b_encrypt(self):
        # FIPS 197, Appendix B: Cipher Example
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(AES_encrypt(plaintext, key), expected)

    def test_appendix_b_decrypt(self):
        # Inverse of FIPS 197 Appendix B vector
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        self.assertEqual(AES_decrypt(ciphertext, key), expected)

    def test_appendix_b_round_trip(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        self.assertEqual(AES_decrypt(AES_encrypt(plaintext, key), key), plaintext)

    def test_appendix_c1_encrypt(self):
        # FIPS 197, Appendix C.1: AES-128
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(AES_encrypt(plaintext, key), expected)

    def test_appendix_c1_decrypt(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        expected = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(AES_decrypt(ciphertext, key), expected)

    def test_appendix_c1_round_trip(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(AES_decrypt(AES_encrypt(plaintext, key), key), plaintext)


if __name__ == "__main__":
    unittest.main()
