"""HMAC-SHA-512 (FIPS 198-1 / RFC 4231).

Pure-Python — depends only on the project's own SHA-512 implementation.
The block size B is 128 bytes (the SHA-512 internal block size).

Project-specific note:
The 16-byte AES key is zero-padded to 128 bytes before XOR with ipad/opad.
The standard-compliance branch for keys longer than 128 bytes is included
(it hashes the oversized key with SHA-512 first, per RFC 2104) even though
ACV never feeds keys > 128 B in practice.
"""

from sha512 import sha512


_BLOCK_SIZE = 128
_IPAD_BYTE = 0x36
_OPAD_BYTE = 0x5C


def _pad_key(key: bytes) -> bytes:
    """Return the B-byte padded key K' per FIPS 198-1 §4."""
    if len(key) > _BLOCK_SIZE:
        # RFC 2104 / FIPS 198-1: long keys are hashed first.
        key = sha512(key)
    if len(key) < _BLOCK_SIZE:
        key = key + b"\x00" * (_BLOCK_SIZE - len(key))
    return key


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA-512(key, message) and return the 64-byte tag."""
    k_prime = _pad_key(key)
    ipad = bytes(b ^ _IPAD_BYTE for b in k_prime)
    opad = bytes(b ^ _OPAD_BYTE for b in k_prime)
    inner = sha512(ipad + message)
    return sha512(opad + inner)


def hmac_equal(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparator.

    Returns True iff `a` and `b` have the same length AND every byte matches.
    The body of the loop runs over the full length so timing is independent
    of where (or whether) the first mismatch occurs. NEVER compare HMAC tags
    with ``==``.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
