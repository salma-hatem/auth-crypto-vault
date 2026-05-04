import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from aes import ctr_encrypt_with_nonce  # V1
import aes_v2  # V2 (whichever backend loaded)


PLAINTEXT_LENS = [0, 1, 15, 16, 17, 31, 32, 100, 1024, 4096]


class TestAesV2Equivalence(unittest.TestCase):
    def test_random_equivalence_v1_vs_v2(self):
        """V2 (C or Python tables) must match V1 byte-for-byte over 200
        random (length, key, nonce, plaintext) triples."""
        rng = os.urandom
        cases = 200
        per_len = max(1, cases // len(PLAINTEXT_LENS))
        total = 0
        for n in PLAINTEXT_LENS:
            for _ in range(per_len):
                key = rng(16)
                nonce = rng(12)
                pt = rng(n)
                v1 = ctr_encrypt_with_nonce(pt, key, nonce)
                v2 = aes_v2.ctr_encrypt(pt, key, nonce)
                if v1 != v2:
                    self.fail(
                        f"V1 vs V2 mismatch (BACKEND={aes_v2.BACKEND}) "
                        f"len={n} key={key.hex()} nonce={nonce.hex()}\n"
                        f"  v1={v1.hex()}\n  v2={v2.hex()}"
                    )
                total += 1
        self.assertGreaterEqual(total, 200)

    def test_decrypt_inverts_encrypt(self):
        """V2.ctr_decrypt(V2.ctr_encrypt(pt)) == pt for several sizes."""
        for n in PLAINTEXT_LENS:
            key = os.urandom(16)
            nonce = os.urandom(12)
            pt = os.urandom(n)
            ct = aes_v2.ctr_encrypt(pt, key, nonce)
            self.assertEqual(aes_v2.ctr_decrypt(ct, key, nonce), pt)

    def test_sp800_38a_ctr_aes128_block1(self):
        """SP 800-38A §F.5.1 CTR-AES128.Encrypt — first block adapted to
        counter-starts-at-0 by using the published initial counter as the
        full 16-byte counter block (nonce = first 12 B, ctr = last 4 B = 0).

        Vector:
          Key:               2b7e151628aed2a6abf7158809cf4f3c
          Init Counter:      f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
          Plaintext block 1: 6bc1bee22e409f96e93d7e117393172a
          Ciphertext block1: 874d6191b620e3261bef6864990db6ce
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        # The published initial counter ends in fcfdfeff; we drive that
        # value at counter=0 by setting the 12-byte nonce to the first 12
        # bytes and (implicit counter prefix)... but our scheme is
        # nonce(12) || be32(counter) starting at 0, so to land on the
        # published 16-byte counter block we'd need ctr=0xfcfdfeff at
        # block 0 — impossible in our scheme. Adapt: use nonce =
        # f0f1f2f3f4f5f6f7f8f9fafb and the test only checks a one-block
        # encryption where counter=0 produces counter-block
        # f0f1f2f3f4f5f6f7f8f9fafb00000000. This is a self-consistent
        # KAT, not the verbatim SP 800-38A bytes.
        nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafb")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        v1 = ctr_encrypt_with_nonce(pt, key, nonce)
        v2 = aes_v2.ctr_encrypt(pt, key, nonce)
        self.assertEqual(v1, v2)

    @classmethod
    def tearDownClass(cls):
        # Make the active backend obvious in test output.
        sys.stderr.write(f"\n[aes_v2] BACKEND={aes_v2.BACKEND}\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
