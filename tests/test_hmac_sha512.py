"""HMAC-SHA-512 known-answer tests against RFC 4231.

Cases 1, 2, 4, 6, 7 specify full-length tags and are the load-bearing
checks. Case 5 in RFC 4231 is the "truncation" test — the RFC publishes
only the first 128 bits, so we assert the truncated prefix matches.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from hmac_kdf import hmac_equal, hmac_sha512


class TestHMACSHA512RFC4231(unittest.TestCase):
    def test_case_1_short_key_short_data(self):
        key = b"\x0b" * 20
        data = b"Hi There"
        expected = bytes.fromhex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        )
        self.assertEqual(hmac_sha512(key, data), expected)

    def test_case_2_text_key(self):
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        )
        self.assertEqual(hmac_sha512(key, data), expected)

    def test_case_4_combined_block_data(self):
        key = bytes(range(0x01, 0x1a))  # 0x01..0x19, 25 bytes
        data = b"\xcd" * 50
        expected = bytes.fromhex(
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
            "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
        )
        self.assertEqual(hmac_sha512(key, data), expected)

    def test_case_5_truncation_first_128_bits(self):
        # RFC 4231 §4.6: only the first 128 bits of the tag are specified.
        # The remaining bits are intentionally not normative (this case
        # exists to test truncated-tag implementations). Our implementation
        # produces the full 64-byte tag; we only assert the published
        # 16-byte prefix here.
        key = b"\x0c" * 20
        data = b"Test With Truncation"
        expected_prefix = bytes.fromhex("415fad6271580a531d4179bc891d87a6")
        self.assertEqual(hmac_sha512(key, data)[:16], expected_prefix)

    def test_case_6_oversize_key(self):
        key = b"\xaa" * 131
        data = b"Test Using Larger Than Block-Size Key - Hash Key First"
        expected = bytes.fromhex(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        )
        self.assertEqual(hmac_sha512(key, data), expected)

    def test_case_7_oversize_key_oversize_data(self):
        key = b"\xaa" * 131
        data = (
            b"This is a test using a larger than block-size key and a larger "
            b"than block-size data. The key needs to be hashed before being "
            b"used by the HMAC algorithm."
        )
        expected = bytes.fromhex(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
            "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        )
        self.assertEqual(hmac_sha512(key, data), expected)


class TestHMACEqual(unittest.TestCase):
    def test_equal_tags(self):
        a = bytes.fromhex("00112233445566778899aabbccddeeff" * 4)
        b = bytes(a)
        self.assertTrue(hmac_equal(a, b))

    def test_different_tags(self):
        a = bytes.fromhex("00112233445566778899aabbccddeeff" * 4)
        b = bytearray(a)
        b[-1] ^= 0x01
        self.assertFalse(hmac_equal(a, bytes(b)))

    def test_first_byte_differs(self):
        a = bytes.fromhex("00112233445566778899aabbccddeeff" * 4)
        b = bytearray(a)
        b[0] ^= 0x80
        self.assertFalse(hmac_equal(a, bytes(b)))

    def test_length_mismatch(self):
        self.assertFalse(hmac_equal(b"abc", b"abcd"))
        self.assertFalse(hmac_equal(b"", b"x"))

    def test_both_empty(self):
        self.assertTrue(hmac_equal(b"", b""))


if __name__ == "__main__":
    unittest.main()
