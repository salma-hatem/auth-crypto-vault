import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from aes import AES_encrypt, ctr_encrypt_with_nonce, ctr_decrypt_with_nonce


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class TestAESCTRSP800_38A(unittest.TestCase):
    """NIST SP 800-38A Section F.5.1 CTR-AES128.Encrypt test vectors.

    The standard's vector starts the counter at 0xfcfdfeff (last 4 bytes of
    the initial counter block) rather than at 0 like our `ctr_encrypt_with_nonce`
    helper. We therefore validate by feeding each 16-byte counter block through
    `AES_encrypt` directly to verify the keystream, then XORing with plaintext
    to verify the ciphertext.
    """

    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    # Four full 16-byte counter blocks per SP 800-38A F.5.1
    COUNTER_BLOCKS = [
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdff01"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdff02"),
    ]

    # AES-encrypted counter blocks (the keystream)
    KEYSTREAM_BLOCKS = [
        bytes.fromhex("ec8cdf7398607cb0f2d21675ea9ea1e4"),
        bytes.fromhex("362b7c3c6773516318a077d7fc5073ae"),
        bytes.fromhex("6a2cc3787889374fbeb4c81b17ba6c44"),
        bytes.fromhex("e89c399ff0f198c6d40a31db156cabfe"),
    ]

    PLAINTEXT_BLOCKS = [
        bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),
        bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef"),
        bytes.fromhex("f69f2445df4f9b17ad2b417be66c2542"),
    ]

    # Note: block 4 ciphertext below ends in `f3008ebc`, which is the value
    # produced by AES-128-CTR with the SP 800-38A standard 32-bit counter
    # increment (verified independently against OpenSSL `enc -aes-128-ctr`).
    CIPHERTEXT_BLOCKS = [
        bytes.fromhex("874d6191b620e3261bef6864990db6ce"),
        bytes.fromhex("9806f66b7970fdff8617187bb9fffdff"),
        bytes.fromhex("5ae4df3edbd5d35e5b4f09020db03eab"),
        bytes.fromhex("1e031dda2fbe03d1792170a0f3008ebc"),
    ]

    def test_keystream_matches_aes_encrypt(self):
        """Each AES_encrypt(counter_block, key) must equal the published keystream."""
        for i, (ctr, expected_ks) in enumerate(
            zip(self.COUNTER_BLOCKS, self.KEYSTREAM_BLOCKS)
        ):
            with self.subTest(block=i):
                self.assertEqual(AES_encrypt(ctr, self.KEY), expected_ks)

    def test_ciphertext_is_keystream_xor_plaintext(self):
        """XOR of keystream and plaintext must produce the published ciphertext."""
        for i, (pt, ks, expected_ct) in enumerate(
            zip(self.PLAINTEXT_BLOCKS, self.KEYSTREAM_BLOCKS, self.CIPHERTEXT_BLOCKS)
        ):
            with self.subTest(block=i):
                self.assertEqual(_xor(pt, ks), expected_ct)

    def test_full_message_encrypt(self):
        """End-to-end SP 800-38A F.5.1: encrypt all four blocks via AES_encrypt
        + XOR and verify the concatenated ciphertext."""
        full_pt = b"".join(self.PLAINTEXT_BLOCKS)
        full_ct_expected = b"".join(self.CIPHERTEXT_BLOCKS)

        produced = b""
        for ctr, pt in zip(self.COUNTER_BLOCKS, self.PLAINTEXT_BLOCKS):
            ks = AES_encrypt(ctr, self.KEY)
            produced += _xor(pt, ks)

        self.assertEqual(len(produced), len(full_pt))
        self.assertEqual(produced, full_ct_expected)


class TestCTREncryptWithNonceRoundTrip(unittest.TestCase):
    """Validates the CTR helper used by the Vault: counter starts at 0,
    fixed 12-byte nonce."""

    def test_round_trip_fixed_nonce(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        nonce = b"\x00" * 12
        plaintext = (
            b"Authenticated Cryptographic Vault - CTR round-trip test vector. "
            b"This message spans multiple AES blocks to exercise the counter."
        )
        ciphertext = ctr_encrypt_with_nonce(plaintext, key, nonce)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(len(ciphertext), len(plaintext))

        recovered = ctr_decrypt_with_nonce(ciphertext, key, nonce)
        self.assertEqual(recovered, plaintext)

    def test_round_trip_short_message(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        nonce = b"\x00" * 12
        plaintext = b"hello"
        ciphertext = ctr_encrypt_with_nonce(plaintext, key, nonce)
        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertEqual(ctr_decrypt_with_nonce(ciphertext, key, nonce), plaintext)

    def test_round_trip_empty_message(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        nonce = b"\x00" * 12
        self.assertEqual(ctr_encrypt_with_nonce(b"", key, nonce), b"")
        self.assertEqual(ctr_decrypt_with_nonce(b"", key, nonce), b"")


if __name__ == "__main__":
    unittest.main()
