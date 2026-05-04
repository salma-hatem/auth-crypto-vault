"""
NIST FIPS 180-4 test vectors for SHA-512.

Vectors taken directly from FIPS 180-4 Appendix C and the NIST CAVP
short-message KAT.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from sha512 import sha512, Sha512


# FIPS 180-4 Appendix C.1 -- one-block message "abc".
ABC_DIGEST = (
    "ddaf35a193617aba"
    "cc417349ae204131"
    "12e6fa4e89a97ea2"
    "0a9eeee64b55d39a"
    "2192992a274fc1a8"
    "36ba3c23a3feebbd"
    "454d4423643ce80e"
    "2a9ac94fa54ca49f"
)

# Empty string -- NIST CAVP / canonical test vector.
EMPTY_DIGEST = (
    "cf83e1357eefb8bd"
    "f1542850d66d8007"
    "d620e4050b5715dc"
    "83f4a921d36ce9ce"
    "47d0d13c5d85f2b0"
    "ff8318d2877eec2f"
    "63b931bd47417a81"
    "a538327af927da3e"
)

# FIPS 180-4 Appendix C.2 -- two-block, 56-character message.
TWO_BLOCK_MSG = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
TWO_BLOCK_DIGEST = (
    "204a8fc6dda82f0a"
    "0ced7beb8e08a416"
    "57c16ef468b228a8"
    "279be331a703c335"
    "96fd15c13b1b07f9"
    "aa1d3bea57789ca0"
    "31ad85c7a71dd703"
    "54ec631238ca3445"
)

# FIPS 180-4 Appendix C.3 -- two-block, 112-character message.
LONG_MSG = (
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
)
LONG_DIGEST = (
    "8e959b75dae313da"
    "8cf4f72814fc143f"
    "8f7779c6eb9f7fa1"
    "7299aeadb6889018"
    "501d289e4900f7e4"
    "331b99dec4b5433a"
    "c7d329eeb6dd2654"
    "5e96e55b874be909"
)

# FIPS 180-4: SHA-512 of one million 'a' characters.
MILLION_A_DIGEST = (
    "e718483d0ce76964"
    "4e2e42c7bc15b463"
    "8e1f98b13b204428"
    "5632a803afa973eb"
    "de0ff244877ea60a"
    "4cb0432ce577c31b"
    "eb009c5c2c49aa2e"
    "4eadb217ad8cc09b"
)


class TestSha512Nist(unittest.TestCase):
    # --- FIPS 180-4 Appendix C ---

    def test_abc(self):
        self.assertEqual(sha512(b"abc").hex(), ABC_DIGEST)

    def test_empty(self):
        self.assertEqual(sha512(b"").hex(), EMPTY_DIGEST)

    def test_two_block_56_chars(self):
        self.assertEqual(sha512(TWO_BLOCK_MSG).hex(), TWO_BLOCK_DIGEST)

    def test_two_block_112_chars(self):
        self.assertEqual(sha512(LONG_MSG).hex(), LONG_DIGEST)

    def test_one_million_a(self):
        self.assertEqual(sha512(b"a" * 1_000_000).hex(), MILLION_A_DIGEST)

    # --- Block-boundary tests ---

    def test_block_boundaries(self):
        for n in (0, 1, 55, 56, 111, 112, 119, 120, 127, 128, 1024, 1025):
            with self.subTest(length=n):
                msg = b"a" * n
                d1 = sha512(msg)
                d2 = sha512(msg)
                self.assertEqual(len(d1), 64)
                self.assertEqual(d1, d2, "digest must be deterministic")

    # --- Streaming API ---

    def test_streaming_matches_oneshot_abc(self):
        h = Sha512()
        h.update(b"a")
        h.update(b"b")
        h.update(b"c")
        self.assertEqual(h.hexdigest(), ABC_DIGEST)

    def test_streaming_matches_oneshot_long(self):
        # Feed the 1M-'a' message in odd-sized chunks.
        h = Sha512()
        msg = b"a" * 1_000_000
        offset = 0
        for chunk_size in (1, 7, 64, 127, 128, 129, 1023, 1024, 1025, 8192):
            end = min(offset + chunk_size, len(msg))
            h.update(msg[offset:end])
            offset = end
        h.update(msg[offset:])
        self.assertEqual(h.hexdigest(), MILLION_A_DIGEST)

    def test_copy_is_independent(self):
        h = Sha512()
        h.update(b"ab")
        h2 = h.copy()
        h.update(b"c")
        h2.update(b"c")
        self.assertEqual(h.hexdigest(), ABC_DIGEST)
        self.assertEqual(h2.hexdigest(), ABC_DIGEST)
        # Diverge after copy.
        h2.update(b"d")
        self.assertNotEqual(h.hexdigest(), h2.hexdigest())

    def test_digest_repeatable_after_call(self):
        # Calling digest() twice must yield the same value (no destructive finalize).
        h = Sha512()
        h.update(b"abc")
        first = h.digest()
        second = h.digest()
        self.assertEqual(first, second)
        self.assertEqual(first.hex(), ABC_DIGEST)

    def test_update_after_digest_continues_message(self):
        # Spec: a finalized hash must still accept further updates and
        # produce the digest of the full concatenation.
        h = Sha512()
        h.update(b"a")
        _ = h.digest()
        h.update(b"bc")
        self.assertEqual(h.hexdigest(), ABC_DIGEST)


if __name__ == "__main__":
    unittest.main()
